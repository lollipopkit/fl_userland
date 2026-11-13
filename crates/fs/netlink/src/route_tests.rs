use super::*;

#[cfg(test)]
mod parser_tests {
    use super::*;

    #[test]
    fn a_sockaddr_of_length_zero_steps_by_four() {
        // A default route's netmask is one. Stepping by zero loops for ever,
        // which is the whole reason SA_SIZE is not `max(len, 1)`.
        assert_eq!(sa_step(0), 4);
        assert_eq!(sa_step(1), 4);
        assert_eq!(sa_step(4), 4);
        assert_eq!(sa_step(5), 8);
        assert_eq!(sa_step(16), 16);
        assert_eq!(sa_step(28), 28);
    }

    #[test]
    fn the_sockaddrs_are_read_in_bitmask_order_not_at_fixed_offsets() {
        // DST and NETMASK, no GATEWAY: a fixed reading takes the netmask for
        // the gateway and prints `default via 255.255.255.0`.
        let dst = [
            16u8,
            libc::AF_INET as u8,
            0,
            0,
            10,
            1,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        let mask = [8u8, libc::AF_INET as u8, 0, 0, 255, 255, 255, 0];
        let mut body = dst.to_vec();
        body.extend_from_slice(&mask);
        let got = sockaddrs(&body, libc::RTA_DST | libc::RTA_NETMASK);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, libc::RTA_DST);
        assert_eq!(got[1].0, libc::RTA_NETMASK);
        assert_eq!(sa_addr(&got[0].1).unwrap().1, vec![10, 1, 2, 0]);
    }

    #[test]
    fn a_length_past_the_buffer_ends_the_walk() {
        // The shape that reads somebody else's memory if it is believed. The
        // kernel is the source here, but the walk is the same walk a guest's
        // bytes would go through if this were ever pointed at one.
        let body = [200u8, libc::AF_INET as u8, 0, 0, 10, 1, 2, 0];
        assert!(sockaddrs(&body, libc::RTA_DST).is_empty());
    }

    #[test]
    fn a_truncated_mask_is_the_same_prefix_as_a_full_one() {
        // Darwin sends 255.255.255.0 as four bytes of sockaddr plus three of
        // mask, and 0.0.0.0 as nothing at all.
        let full = [8u8, libc::AF_INET as u8, 0, 0, 255, 255, 255, 0];
        assert_eq!(mask_prefix_len(&full, 4), 24);
        let short = [7u8, libc::AF_INET as u8, 0, 0, 255, 255, 255];
        assert_eq!(mask_prefix_len(&short, 4), 24, "the missing byte is zero");
        let empty: [u8; 0] = [];
        assert_eq!(mask_prefix_len(&empty, 4), 0, "a default route");
        let host = [8u8, libc::AF_INET as u8, 0, 0, 255, 255, 255, 255];
        assert_eq!(mask_prefix_len(&host, 4), 32);
    }

    #[test]
    fn a_link_level_gateway_has_no_address_for_a_guest() {
        // An on-link route's gateway is an AF_LINK sockaddr naming the
        // interface. Reported as "no gateway", which is what Linux's table
        // says for the same route.
        let dl = [
            20u8,
            libc::AF_LINK as u8,
            0,
            0,
            6,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(sa_addr(&dl).is_none());
    }

    #[test]
    fn only_the_three_flags_a_reader_decodes_are_translated() {
        assert_eq!(linux_route_flags(libc::RTF_UP), RTF_UP);
        assert_eq!(
            linux_route_flags(libc::RTF_UP | libc::RTF_GATEWAY),
            RTF_UP | RTF_GATEWAY
        );
        assert_eq!(
            linux_route_flags(libc::RTF_UP | libc::RTF_HOST),
            RTF_UP | RTF_HOST
        );
        // And nothing else leaks through: Darwin's RTF_LLINFO is 0x400 and
        // Linux's RTF_REJECT is 0x0200, so a passed-through word lies.
        assert_eq!(linux_route_flags(0x400), 0);
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;

    /// The machine's own table, which is what a guest is shown.
    ///
    /// Asserts about *shape* rather than about contents, because the contents
    /// are this machine's: whatever routes there are, each has an interface
    /// this kernel also reports, a destination the right length for its family,
    /// and a prefix that fits in it. A machine with no routes at all fails,
    /// which is a check on the reader rather than on the machine -- `sysctl`
    /// answering nothing and the parse answering nothing look the same from
    /// here, and the first is a defect.
    #[test]
    fn the_hosts_table_reads_back_as_routes_a_guest_could_use() {
        let routes = host_routes();
        assert!(
            !routes.is_empty(),
            "no routes at all -- the sysctl or the parse"
        );
        let ifaces = crate::host_ifaces();
        for r in &routes {
            let len = if r.family == 2 { 4 } else { 16 };
            assert_eq!(r.dst.len(), len, "{r:?}");
            assert!(r.prefix_len as usize <= len * 8, "{r:?}");
            assert!(r.flags & RTF_UP != 0, "only up routes are reported: {r:?}");
            assert!(
                ifaces
                    .iter()
                    .any(|i| i.index == r.if_index && i.name == r.if_name),
                "a route out of an interface the link dump does not name: {r:?}"
            );
            if !r.gateway.is_empty() {
                assert_eq!(r.gateway.len(), len, "{r:?}");
            }
        }
        // The one route a machine on a network has, and the one every reader
        // of this table is looking for.
        assert!(
            routes.iter().any(|r| r.prefix_len == 0 && r.family == 2),
            "no IPv4 default route: {routes:#?}"
        );
    }
}

#[cfg(test)]
mod query_tests {
    use super::*;

    fn r(dst: [u8; 4], prefix: u8, gw: Vec<u8>, name: &str) -> Route {
        Route {
            family: 2,
            dst: dst.to_vec(),
            prefix_len: prefix,
            gateway: gw,
            if_index: 1,
            if_name: name.into(),
            flags: RTF_UP,
            metric: 0,
        }
    }

    #[test]
    fn the_longest_prefix_wins_over_the_default() {
        let table = vec![
            r([0, 0, 0, 0], 0, vec![192, 168, 1, 1], "en0"),
            r([10, 0, 0, 0], 8, vec![], "utun0"),
            r([10, 1, 0, 0], 16, vec![], "utun1"),
        ];
        assert_eq!(lookup(&table, 2, &[8, 8, 8, 8]).unwrap().if_name, "en0");
        assert_eq!(lookup(&table, 2, &[10, 2, 3, 4]).unwrap().if_name, "utun0");
        assert_eq!(lookup(&table, 2, &[10, 1, 3, 4]).unwrap().if_name, "utun1");
    }

    #[test]
    fn among_equally_specific_routes_the_first_wins() {
        // This machine has four default routes -- two VPN tunnels, a bridge and
        // the real interface -- and only one has a gateway. `parse_dump` puts
        // that one first; `max_by_key` answers the *last* maximum and chose a
        // tunnel, so `ip route get 8.8.8.8` said `dev utun8 scope link`.
        let table = vec![
            r([0, 0, 0, 0], 0, vec![192, 168, 31, 1], "en0"),
            r([0, 0, 0, 0], 0, vec![], "utun10"),
            r([0, 0, 0, 0], 0, vec![], "bridge100"),
            r([0, 0, 0, 0], 0, vec![], "utun8"),
        ];
        assert_eq!(lookup(&table, 2, &[8, 8, 8, 8]).unwrap().if_name, "en0");
    }

    #[test]
    fn a_prefix_that_is_not_a_whole_number_of_bytes_matches_on_the_bits() {
        // 172.16.0.0/12 covers 172.16 through 172.31 and not 172.32. Rounding
        // the prefix down to one byte would match all of 172/8.
        let t = [r([172, 16, 0, 0], 12, vec![], "en0")];
        assert!(covers(&t[0], &[172, 16, 0, 1]));
        assert!(covers(&t[0], &[172, 31, 255, 254]));
        assert!(!covers(&t[0], &[172, 32, 0, 1]));
        assert!(!covers(&t[0], &[172, 15, 255, 255]));
        assert!(!covers(&t[0], &[173, 16, 0, 1]));
    }

    #[test]
    fn a_default_route_covers_everything_and_a_host_route_covers_one() {
        let d = r([0, 0, 0, 0], 0, vec![1, 2, 3, 4], "en0");
        assert!(covers(&d, &[0, 0, 0, 0]));
        assert!(covers(&d, &[255, 255, 255, 255]));
        let h = r([10, 1, 2, 3], 32, vec![], "en0");
        assert!(covers(&h, &[10, 1, 2, 3]));
        assert!(!covers(&h, &[10, 1, 2, 4]));
    }

    #[test]
    fn a_family_with_no_route_answers_nothing_rather_than_the_wrong_one() {
        let table = vec![r([0, 0, 0, 0], 0, vec![192, 168, 1, 1], "en0")];
        assert!(lookup(&table, 10, &[0u8; 16]).is_none());
        // And a v6 address against a v4 table, which differ in length as well
        // as in family -- either check alone would let one through.
        assert!(lookup(&table, 2, &[0u8; 16]).is_none());
    }

    #[test]
    fn a_global_source_address_is_preferred_to_a_link_local_one() {
        // An interface with both. Binding to fe80:: reaches nothing off the
        // link, so it is the fallback rather than the answer.
        let iface = crate::Iface {
            index: 3,
            name: "en0".into(),
            mac: vec![],
            mtu: 1500,
            flags: 0,
            loopback: false,
            addrs: vec![
                (libc::AF_INET6 as u8, 64, {
                    let mut a = vec![0xfe, 0x80];
                    a.resize(16, 0);
                    a
                }),
                (libc::AF_INET6 as u8, 64, {
                    let mut a = vec![0x20, 0x01];
                    a.resize(16, 0);
                    a
                }),
                (libc::AF_INET as u8, 24, vec![192, 168, 1, 5]),
            ],
        };
        let v6 = preferred_src(&[iface], 3, 10).unwrap();
        assert_eq!(v6[0], 0x20, "the global one, not fe80::");
        let v4 = preferred_src(std::slice::from_ref(&make(3)), 3, 2);
        assert_eq!(v4, Some(vec![192, 168, 1, 5]));
        assert!(
            preferred_src(&[make(3)], 99, 2).is_none(),
            "no such interface"
        );
    }

    fn make(index: u32) -> crate::Iface {
        crate::Iface {
            index,
            name: "en0".into(),
            mac: vec![],
            mtu: 1500,
            flags: 0,
            loopback: false,
            addrs: vec![(libc::AF_INET as u8, 24, vec![192, 168, 1, 5])],
        }
    }
}

#[cfg(test)]
mod neighbour_tests {
    use super::*;

    #[test]
    fn a_macs_offset_is_the_name_length_not_a_constant() {
        // sdl_data holds the interface name and *then* the hardware address.
        // "en0" is three bytes, so the MAC starts at 8 + 3. Reading from 8
        // answers "en0" plus the first three bytes of the address.
        let mut sa = vec![0u8; 20];
        sa[0] = 20; // sdl_len
        sa[1] = libc::AF_LINK as u8;
        sa[5] = 3; // sdl_nlen
        sa[6] = 6; // sdl_alen
        sa[8..11].copy_from_slice(b"en0");
        sa[11..17].copy_from_slice(&[0xca, 0x7e, 0x8f, 0x25, 0xd7, 0x09]);
        assert_eq!(sdl_mac(&sa), vec![0xca, 0x7e, 0x8f, 0x25, 0xd7, 0x09]);

        // An entry with no name is the other end of the same rule.
        let mut bare = vec![0u8; 14];
        bare[0] = 14;
        bare[1] = libc::AF_LINK as u8;
        bare[6] = 6;
        bare[8..14].copy_from_slice(&[1, 2, 3, 4, 5, 6]);
        assert_eq!(sdl_mac(&bare), vec![1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn an_unresolved_entry_has_no_hardware_address() {
        // sdl_alen 0: the neighbour has been asked for and has not answered.
        // `arp -a` prints `<incomplete>` and the flags column is 0.
        let mut sa = vec![0u8; 12];
        sa[0] = 12;
        sa[1] = libc::AF_LINK as u8;
        sa[5] = 3;
        sa[8..11].copy_from_slice(b"en0");
        assert!(sdl_mac(&sa).is_empty());
    }

    #[test]
    fn a_gateway_that_is_not_a_link_address_is_not_a_mac() {
        // An AF_INET gateway is a next hop, not a hardware address. Read as a
        // sockaddr_dl its bytes 5 and 6 are part of the port and the address.
        let sa = [
            16u8,
            libc::AF_INET as u8,
            0,
            0,
            10,
            1,
            2,
            3,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ];
        assert!(sdl_mac(&sa).is_empty());
    }
}
