//! Epoll nesting graph and cycle/depth validation.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

#[cfg(test)]
use crate::api::error_code;
use crate::{Epoll, Error};
#[cfg(test)]
use libc::c_int;

const MAX_NESTING_EDGES: usize = 4;

/// Which epoll set: a key in [`Graph::edges`], and one arm of [`GraphNode`].
///
/// A bare `usize` until 2026-09-15, as was [`FileId`] — **three kinds of
/// address in one module, all the same type.** `edges` was keyed on a set,
/// `GraphNode::Epoll` held a set, `GraphNode::File` and the `leaves` set held
/// a member, and `reaches(start, target)` took two sets. Every one of them was
/// `usize`, so `reaches(file, set)` and `collect_leaves(file, …)` type-checked
/// as readily as the right call.
///
/// Not [`iul_abi::Identity`], deliberately: the member side is genuinely
/// type-erased — `epoll_add` is generic over `M::Member` and this graph does
/// not care what one is — so `Identity<T>` has no `T` to name. What the graph
/// needs is two *kinds* of identity, which is two newtypes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(crate) struct SetId(usize);

/// Which member description. See [`SetId`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub(crate) struct FileId(usize);

impl SetId {
    pub(crate) fn of(epoll: &Epoll) -> SetId {
        SetId(std::ptr::from_ref(epoll) as usize)
    }

    /// From an address, for the tests — which name sets as `1`, `2`, `40`
    /// rather than building them, and can because the graph compares its ids
    /// and never reads through one.
    #[cfg(test)]
    pub(crate) fn raw(addr: usize) -> SetId {
        SetId(addr)
    }
}

impl FileId {
    /// Takes a reference, as [`SetId::of`] does: `epoll_add` has one since
    /// 2026-09-16, and a graph id built from a pointer could be built from a
    /// null.
    pub(crate) fn of<T>(member: &T) -> FileId {
        FileId(std::ptr::from_ref(member) as usize)
    }

    #[cfg(test)]
    pub(crate) fn raw(addr: usize) -> FileId {
        FileId(addr)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum GraphNode {
    Epoll(SetId),
    File(FileId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GraphEdge {
    target: GraphNode,
    registrations: usize,
}

#[derive(Default)]
pub(crate) struct Graph {
    pub(crate) edges: HashMap<SetId, Vec<GraphEdge>>,
}

#[derive(Debug)]
pub(crate) enum GraphAddPlan {
    Existing { outer: SetId, index: usize },
    NewAtOuter { outer: SetId, target: GraphNode },
    NewOuter { outer: SetId, edges: Vec<GraphEdge> },
}

#[derive(Clone, Copy)]
struct ExtraEdge {
    outer: SetId,
    target: GraphNode,
}

impl Graph {
    fn outgoing(&self, node: SetId, extra: Option<ExtraEdge>) -> Vec<GraphNode> {
        let mut outgoing: Vec<_> = self
            .edges
            .get(&node)
            .into_iter()
            .flatten()
            .map(|edge| edge.target)
            .collect();
        if extra.is_some_and(|extra| extra.outer == node) {
            outgoing.push(extra.expect("checked extra edge").target);
        }
        outgoing
    }

    fn outgoing_counted(&self, node: SetId, extra: Option<ExtraEdge>) -> Vec<GraphNode> {
        let mut outgoing = Vec::new();
        for edge in self.edges.get(&node).into_iter().flatten() {
            outgoing.extend(std::iter::repeat_n(edge.target, edge.registrations));
        }
        if extra.is_some_and(|extra| extra.outer == node) {
            outgoing.push(extra.expect("checked extra edge").target);
        }
        outgoing
    }

    fn reaches(&self, start: SetId, target: SetId) -> bool {
        self.reaches_with(start, target, None)
    }

    fn reaches_with(&self, start: SetId, target: SetId, extra: Option<ExtraEdge>) -> bool {
        start == target
            || self
                .outgoing(start, extra)
                .into_iter()
                .any(|node| match node {
                    GraphNode::Epoll(next) => self.reaches_with(next, target, extra),
                    GraphNode::File(_) => false,
                })
    }

    fn longest_from(&self, node: SetId) -> usize {
        self.outgoing(node, None)
            .into_iter()
            .filter_map(|node| match node {
                GraphNode::Epoll(next) => Some(1 + self.longest_from(next)),
                GraphNode::File(_) => None,
            })
            .max()
            .unwrap_or(0)
    }

    fn longest_to(&self, node: SetId) -> usize {
        self.edges
            .iter()
            .flat_map(|(&outer, edges)| {
                edges
                    .iter()
                    .filter(move |edge| edge.target == GraphNode::Epoll(node))
                    .map(move |_| outer)
            })
            .map(|outer| 1 + self.longest_to(outer))
            .max()
            .unwrap_or(0)
    }

    fn path_limits_hold(&self, extra: ExtraEdge) -> bool {
        const LIMITS: [usize; 5] = [usize::MAX, 500, 100, 50, 10];
        let mut leaves = HashSet::new();
        match extra.target {
            GraphNode::File(file) => {
                leaves.insert(file);
            }
            GraphNode::Epoll(inner) => self.collect_leaves(inner, &mut leaves),
        }
        for leaf in leaves {
            let mut counts = [0usize; 5];
            if !self.count_reverse_paths(
                GraphNode::File(leaf),
                0,
                Some(extra),
                &mut counts,
                &LIMITS,
            ) {
                return false;
            }
        }
        true
    }

    fn collect_leaves(&self, node: SetId, leaves: &mut HashSet<FileId>) {
        for target in self.outgoing_counted(node, None) {
            match target {
                GraphNode::Epoll(inner) => self.collect_leaves(inner, leaves),
                GraphNode::File(file) => {
                    leaves.insert(file);
                }
            }
        }
    }

    fn incoming(&self, target: GraphNode, extra: Option<ExtraEdge>) -> Vec<SetId> {
        let mut incoming = Vec::new();
        for (&outer, edges) in &self.edges {
            for edge in edges.iter().filter(|edge| edge.target == target) {
                incoming.extend(std::iter::repeat_n(outer, edge.registrations));
            }
        }
        if extra.is_some_and(|extra| extra.target == target) {
            incoming.push(extra.expect("checked extra edge").outer);
        }
        incoming
    }

    fn count_reverse_paths(
        &self,
        target: GraphNode,
        depth: usize,
        extra: Option<ExtraEdge>,
        counts: &mut [usize; 5],
        limits: &[usize; 5],
    ) -> bool {
        if depth > MAX_NESTING_EDGES {
            return false;
        }
        for parent in self.incoming(target, extra) {
            let grandparents = self.incoming(GraphNode::Epoll(parent), extra);
            if grandparents.is_empty() {
                if depth > 0 {
                    counts[depth] += 1;
                    if counts[depth] > limits[depth] {
                        return false;
                    }
                }
            } else if !self.count_reverse_paths(
                GraphNode::Epoll(parent),
                depth + 1,
                extra,
                counts,
                limits,
            ) {
                return false;
            }
        }
        true
    }

    pub(crate) fn prepare_add(
        &mut self,
        outer: SetId,
        target: GraphNode,
    ) -> Result<GraphAddPlan, Error> {
        if let Some((index, edge)) = self.edges.get(&outer).and_then(|edges| {
            edges
                .iter()
                .enumerate()
                .find(|(_, edge)| edge.target == target)
        }) {
            if edge.registrations == usize::MAX {
                return Err(Error::OutOfMemory);
            }
            return Ok(GraphAddPlan::Existing { outer, index });
        }

        let extra = ExtraEdge { outer, target };
        if let GraphNode::Epoll(inner) = target
            && (self.reaches(inner, outer)
                || self.longest_to(outer) + 1 + self.longest_from(inner) > MAX_NESTING_EDGES)
        {
            return Err(Error::Loop);
        }
        if !self.path_limits_hold(extra) {
            return Err(Error::Invalid);
        }

        if let Some(edges) = self.edges.get_mut(&outer) {
            if edges.try_reserve(1).is_err() {
                return Err(Error::OutOfMemory);
            }
            return Ok(GraphAddPlan::NewAtOuter { outer, target });
        }

        if self.edges.try_reserve(1).is_err() {
            return Err(Error::OutOfMemory);
        }
        let mut edges = Vec::new();
        if edges.try_reserve(1).is_err() {
            return Err(Error::OutOfMemory);
        }
        Ok(GraphAddPlan::NewOuter { outer, edges })
    }

    pub(crate) fn commit_add(&mut self, plan: GraphAddPlan, target: GraphNode) {
        match plan {
            GraphAddPlan::Existing { outer, index } => {
                self.edges.get_mut(&outer).expect("prepared outer")[index].registrations += 1;
            }
            GraphAddPlan::NewAtOuter { outer, target } => {
                self.edges
                    .get_mut(&outer)
                    .expect("prepared outer")
                    .push(GraphEdge {
                        target,
                        registrations: 1,
                    });
            }
            GraphAddPlan::NewOuter { outer, mut edges } => {
                edges.push(GraphEdge {
                    target,
                    registrations: 1,
                });
                self.edges.insert(outer, edges);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn add(&mut self, outer: SetId, inner: SetId) -> c_int {
        self.add_target(outer, GraphNode::Epoll(inner))
    }

    #[cfg(test)]
    pub(crate) fn add_target(&mut self, outer: SetId, target: GraphNode) -> c_int {
        let plan = match self.prepare_add(outer, target) {
            Ok(plan) => plan,
            Err(error) => return error_code(error),
        };
        self.commit_add(plan, target);
        0
    }

    pub(crate) fn remove(&mut self, outer: SetId, target: GraphNode, count: usize) {
        let mut remove_outer = false;
        if let Some(edges) = self.edges.get_mut(&outer) {
            if let Some(index) = edges.iter().position(|edge| edge.target == target) {
                if edges[index].registrations > count {
                    edges[index].registrations -= count;
                } else {
                    edges.swap_remove(index);
                }
            }
            remove_outer = edges.is_empty();
        }
        if remove_outer {
            self.edges.remove(&outer);
        }
    }
}

pub(crate) static GRAPH: Mutex<Option<Graph>> = Mutex::new(None);

pub(crate) fn with_graph<R>(f: impl FnOnce(&mut Graph) -> R) -> R {
    let mut graph = GRAPH
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    f(graph.get_or_insert_with(Graph::default))
}

/// A set is being destroyed: it is neither an outer nor a target any more.
///
/// Still a `*mut Epoll` rather than a `&Epoll`: the caller is `Epoll::drop`,
/// and forming a reference to a value that is being dropped is what this must
/// not do. `SetId` is built from the address without reading through it, which
/// is the whole reason the type exists.
pub(crate) fn graph_remove_node(node: &Epoll) {
    with_graph(|graph| {
        let node = SetId::of(node);
        graph.edges.remove(&node);
        graph.edges.retain(|_, edges| {
            edges.retain(|edge| edge.target != GraphNode::Epoll(node));
            !edges.is_empty()
        });
    });
}
