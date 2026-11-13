//! Unit tests for netlink message encoding and host interface adapters.

use super::*;

mod protocol_tests {
    use super::*;

    #[test]
    fn the_structure_sizes_are_the_headers() {
        // `linux/netlink.h` and `linux/if_link.h`. Written out because this
        // crate generates no bindings -- there is no Linux header on the host
        // to generate them from, which is the reason the numbers are here and
        // the reason they need a test.
        assert_eq!(NLMSG_HDRLEN, 16);
        assert_eq!(IFINFOMSG_LEN, 16);
        assert_eq!(IFADDRMSG_LEN, 8);
        assert_eq!(RTA_HDRLEN, 4);
    }

    #[test]
    fn alignment_is_to_four_and_is_not_a_round_up_of_the_length_field() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(16), 16);
        assert_eq!(align4(17), 20);
    }

    #[test]
    fn a_message_records_its_own_length_without_the_padding() {
        let mut out = Vec::new();
        let mut m = Message::new(&mut out, RTM_NEWLINK, NLM_F_MULTI, 7, 0);
        m.body(&ifinfomsg(1, ARPHRD_LOOPBACK, 0x49));
        m.attr(IFLA_IFNAME, b"lo\0");
        m.finish(&mut out);

        let len = u32::from_le_bytes(out[0..4].try_into().unwrap()) as usize;
        // 16 header + 16 ifinfomsg + (4 + 3 padded to 8) = 40.
        assert_eq!(len, 40, "the length counts the header and the attributes");
        assert_eq!(out.len(), 40, "and this one needed no padding");
        assert_eq!(
            u16::from_le_bytes(out[4..6].try_into().unwrap()),
            RTM_NEWLINK
        );
        assert_eq!(
            u16::from_le_bytes(out[6..8].try_into().unwrap()),
            NLM_F_MULTI
        );
        assert_eq!(u32::from_le_bytes(out[8..12].try_into().unwrap()), 7);
    }

    #[test]
    fn an_attributes_length_excludes_its_padding_and_the_next_one_does_not() {
        // The rule that puts every later attribute four bytes late when it is
        // got wrong: `rta_len` counts the header and the payload, the *reader*
        // steps by the aligned length, and a three-byte name occupies eight.
        let mut out = Vec::new();
        let mut m = Message::new(&mut out, RTM_NEWLINK, 0, 1, 0);
        m.attr(IFLA_IFNAME, b"lo\0");
        m.attr(IFLA_MTU, &1500u32.to_le_bytes());
        m.finish(&mut out);

        let first = u16::from_le_bytes(out[16..18].try_into().unwrap()) as usize;
        assert_eq!(first, 7, "4 + 3, not the 8 it occupies");
        let second_at = NLMSG_HDRLEN + align4(first);
        assert_eq!(second_at, 24);
        assert_eq!(
            u16::from_le_bytes(out[second_at..second_at + 2].try_into().unwrap()),
            8
        );
        assert_eq!(
            u16::from_le_bytes(out[second_at + 2..second_at + 4].try_into().unwrap()),
            IFLA_MTU
        );
        assert_eq!(
            u32::from_le_bytes(out[second_at + 4..second_at + 8].try_into().unwrap()),
            1500
        );
    }

    #[test]
    fn two_messages_in_one_buffer_are_both_found() {
        let mut out = Vec::new();
        let mut a = Message::new(&mut out, RTM_NEWLINK, NLM_F_MULTI, 1, 0);
        a.body(&ifinfomsg(1, ARPHRD_LOOPBACK, 0));
        a.attr(IFLA_IFNAME, b"lo\0");
        a.finish(&mut out);
        let mut b = Message::new(&mut out, RTM_NEWLINK, NLM_F_MULTI, 1, 0);
        b.body(&ifinfomsg(2, ARPHRD_ETHER, 0));
        b.attr(IFLA_IFNAME, b"eth0\0");
        b.finish(&mut out);
        done(&mut out, 1, 0);

        let msgs = parse(&out);
        assert_eq!(msgs.len(), 3, "two links and the DONE");
        assert_eq!(msgs[0].kind, RTM_NEWLINK);
        assert_eq!(msgs[1].kind, RTM_NEWLINK);
        assert_eq!(msgs[2].kind, NLMSG_DONE);
    }

    #[test]
    fn a_truncated_tail_ends_the_walk_and_keeps_what_came_before() {
        let mut out = Vec::new();
        let mut m = Message::new(&mut out, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP, 5, 0);
        m.body(&ifinfomsg(0, 0, 0));
        m.finish(&mut out);
        out.extend_from_slice(&[0xff, 0xff, 0xff]); // three bytes, not a header

        let msgs = parse(&out);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].kind, RTM_GETLINK);
        assert_eq!(msgs[0].flags, NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(msgs[0].seq, 5);
    }

    #[test]
    fn a_length_that_lies_ends_the_walk_rather_than_reading_past_the_buffer() {
        // A guest can send anything. A length longer than the buffer is the
        // shape that reads somebody else's memory if it is believed.
        let mut buf = vec![0u8; NLMSG_HDRLEN];
        buf[0..4].copy_from_slice(&9999u32.to_le_bytes());
        assert!(parse(&buf).is_empty());
        // And one shorter than a header, which would otherwise loop for ever.
        buf[0..4].copy_from_slice(&4u32.to_le_bytes());
        assert!(parse(&buf).is_empty());
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert!(parse(&buf).is_empty());
    }

    #[test]
    fn an_error_carries_a_negative_errno_and_the_request_it_refuses() {
        let mut req = Vec::new();
        let m = Message::new(&mut req, 99, NLM_F_REQUEST, 42, 0);
        m.finish(&mut req);

        let mut out = Vec::new();
        error(&mut out, 95, 42, 0, &req);
        let msgs = parse(&out);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0].kind, NLMSG_ERROR);
        assert_eq!(msgs[0].seq, 42);
        let errno = i32::from_le_bytes(out[16..20].try_into().unwrap());
        assert_eq!(errno, -95, "negative, which is what a reader negates");
        // The copy of the refused header, which is how a caller matches it up.
        assert_eq!(&out[20..20 + NLMSG_HDRLEN], &req[..NLMSG_HDRLEN]);
    }

    #[test]
    fn a_done_says_the_dump_has_ended() {
        let mut out = Vec::new();
        done(&mut out, 3, 0);
        let msgs = parse(&out);
        assert_eq!(msgs[0].kind, NLMSG_DONE);
        // NLM_F_MULTI on the DONE too: Linux sets it, and a reader that checks
        // the flag before the type would otherwise stop one message early.
        assert_eq!(msgs[0].flags & NLM_F_MULTI, NLM_F_MULTI);
    }

    #[test]
    fn an_ifinfomsg_puts_the_index_where_a_reader_looks() {
        let b = ifinfomsg(3, ARPHRD_ETHER, 0x1043);
        assert_eq!(b[0], libc::AF_UNSPEC as u8);
        assert_eq!(
            u16::from_le_bytes(b[2..4].try_into().unwrap()),
            ARPHRD_ETHER
        );
        assert_eq!(i32::from_le_bytes(b[4..8].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(b[8..12].try_into().unwrap()), 0x1043);
    }

    #[test]
    fn an_ifaddrmsg_is_eight_bytes_with_the_index_last() {
        let b = ifaddrmsg(libc::AF_INET as u8, 24, 0, 2);
        assert_eq!(b[0], libc::AF_INET as u8);
        assert_eq!(b[1], 24, "the prefix length, which is how a mask is sent");
        assert_eq!(u32::from_le_bytes(b[4..8].try_into().unwrap()), 2);
    }
}

#[cfg(test)]
mod host_tests {
    use super::*;

    #[test]
    fn the_hosts_own_interfaces_are_there_and_one_is_a_loopback() {
        let ifs = host_ifaces();
        assert!(!ifs.is_empty(), "the host has interfaces");
        let lo = ifs.iter().find(|i| i.loopback);
        assert!(
            lo.is_some(),
            "one of them is a loopback: {:?}",
            ifs.iter().map(|i| &i.name).collect::<Vec<_>>()
        );
        let lo = lo.unwrap();
        assert!(
            lo.flags & IFF_LOOPBACK != 0,
            "and says so in Linux's flag word"
        );
        assert!(lo.flags & IFF_UP != 0, "and is up");
        assert!(lo.mtu > 0, "with an MTU: {}", lo.mtu);
        // 127.0.0.1 is on it, which is the address every reader looks for.
        assert!(
            lo.addrs
                .iter()
                .any(|(f, _, b)| *f == libc::AF_INET as u8 && b == &[127, 0, 0, 1]),
            "and 127.0.0.1"
        );
        // Every interface has an index and a name, which is what the dump keys
        // on -- a zero index is the "no such interface" a reader checks for.
        for i in &ifs {
            assert!(i.index > 0, "{} has an index", i.name);
            assert!(!i.name.is_empty());
        }
    }

    #[test]
    fn a_link_local_address_is_link_scope_wherever_it_is() {
        // The one that matters: fe80:: on an interface whose other addresses
        // are global. A reader picking a source address filters on the scope,
        // and a link-local offered as universe is offered for traffic that
        // cannot use it.
        let mut ll = [0u8; 16];
        ll[0] = 0xfe;
        ll[1] = 0x80;
        assert_eq!(scope_of(libc::AF_INET6 as u8, &ll), RT_SCOPE_LINK);
        let mut global = [0u8; 16];
        global[0] = 0x24;
        assert_eq!(scope_of(libc::AF_INET6 as u8, &global), RT_SCOPE_UNIVERSE);
        let mut lo6 = [0u8; 16];
        lo6[15] = 1;
        assert_eq!(scope_of(libc::AF_INET6 as u8, &lo6), RT_SCOPE_HOST);
        assert_eq!(
            scope_of(libc::AF_INET as u8, &[127, 0, 0, 1]),
            RT_SCOPE_HOST
        );
        assert_eq!(
            scope_of(libc::AF_INET as u8, &[169, 254, 1, 1]),
            RT_SCOPE_LINK
        );
        assert_eq!(
            scope_of(libc::AF_INET as u8, &[192, 168, 1, 1]),
            RT_SCOPE_UNIVERSE
        );
        // fec0:: is site-local and deprecated, and is *not* fe80::/10 -- the
        // mask is what separates them, and `a[0] == 0xfe` alone would not.
        let mut site = [0u8; 16];
        site[0] = 0xfe;
        site[1] = 0xc0;
        assert_eq!(scope_of(libc::AF_INET6 as u8, &site), RT_SCOPE_UNIVERSE);
    }

    #[test]
    fn the_address_family_is_translated_too() {
        // Darwin's AF_INET6 is 30 and Linux's is 10. `ip addr` printed
        // `family 30 ???/128` before this, which is what an unmapped number
        // looks like when the two sides disagree -- and the flag word one field
        // along already had a comment saying so.
        assert_eq!(linux_family(libc::AF_INET as u8), 2);
        assert_eq!(linux_family(libc::AF_INET6 as u8), 10);
        assert_ne!(
            libc::AF_INET6,
            10,
            "which is the reason this function exists"
        );
        assert_eq!(
            linux_family(libc::AF_UNIX as u8),
            0,
            "and nothing else passes"
        );
    }

    #[test]
    fn a_netmask_becomes_the_prefix_length_netlink_carries() {
        assert_eq!(prefix_len(&[255, 255, 255, 0]), 24);
        assert_eq!(prefix_len(&[255, 255, 255, 255]), 32);
        assert_eq!(prefix_len(&[255, 0, 0, 0]), 8);
        assert_eq!(prefix_len(&[0, 0, 0, 0]), 0);
        assert_eq!(prefix_len(&[255; 16]), 128, "and a v6 mask");
    }

    #[test]
    fn the_flag_word_is_translated_rather_than_passed_through() {
        // Darwin's IFF_MULTICAST is 0x8000 and Linux's is 0x1000. A word handed
        // over unmapped says the interface is IFF_MASTER (0x400) and
        // IFF_SLAVE (0x800) instead, which is what a bonding-aware reader acts
        // on. The same shape as the signal table this repository records
        // delivering SIGUSR1 as SIGBUS.
        assert_eq!(linux_flags(0x8000), IFF_MULTICAST);
        assert_eq!(linux_flags(0x1), IFF_UP);
        assert_eq!(linux_flags(0x8), IFF_LOOPBACK);
        // A host bit nobody maps is dropped rather than forwarded.
        assert_eq!(linux_flags(0x400), 0, "IFF_SIMPLEX is Darwin's alone");
        assert_eq!(
            linux_flags(0x1 | 0x8 | 0x40 | 0x8000),
            IFF_UP | IFF_LOOPBACK | IFF_RUNNING | IFF_LOWER_UP | IFF_MULTICAST,
            "a running interface has its carrier up, which `ip` shows as LOWER_UP"
        );
    }

    #[test]
    fn a_link_dump_of_the_host_parses_back() {
        let ifs = host_ifaces();
        let bytes = links(&ifs, 1, 0);
        let msgs = parse(&bytes);
        assert_eq!(msgs.len(), ifs.len() + 1, "one per interface and a DONE");
        assert_eq!(msgs.last().unwrap().kind, NLMSG_DONE);
        for m in &msgs[..msgs.len() - 1] {
            assert_eq!(m.kind, RTM_NEWLINK);
            assert_eq!(m.flags & NLM_F_MULTI, NLM_F_MULTI);
        }
    }

    #[test]
    fn an_address_dump_names_every_address_once() {
        let ifs = host_ifaces();
        let want: usize = ifs.iter().map(|i| i.addrs.len()).sum();
        let msgs = parse(&addrs(&ifs, 1, 0));
        assert_eq!(msgs.len(), want + 1);
        assert!(want > 0, "the host has at least one address");
    }
}

#[cfg(test)]
mod ioctl_tests {
    use super::*;

    fn sample() -> Vec<Iface> {
        vec![
            Iface {
                index: 1,
                name: "lo".into(),
                mac: Vec::new(),
                mtu: 65536,
                flags: 0x9,
                loopback: true,
                addrs: vec![(libc::AF_INET as u8, 8, vec![127, 0, 0, 1])],
            },
            Iface {
                index: 2,
                name: "eth0".into(),
                mac: vec![0x02, 0x42, 0xac, 0x11, 0x00, 0x02],
                mtu: 1500,
                flags: 0x1043,
                loopback: false,
                addrs: vec![
                    (libc::AF_INET as u8, 24, vec![192, 168, 1, 5]),
                    (libc::AF_INET as u8, 16, vec![10, 0, 0, 7]),
                ],
            },
        ]
    }

    fn req_for(name: &str) -> Vec<u8> {
        let mut r = vec![0u8; IFREQ_LEN];
        r[..name.len()].copy_from_slice(name.as_bytes());
        r
    }

    #[test]
    fn the_sizes_are_the_ones_an_arm64_kernel_reports() {
        // Measured in a container, because there is no Linux header here to
        // generate them from: a wrong `IFREQ_LEN` puts every entry of a
        // SIOCGIFCONF array at the wrong offset and `ifconfig` reads rubbish.
        assert_eq!(IFREQ_LEN, 40);
        assert_eq!(IFCONF_LEN, 16);
        assert_eq!(IFNAMSIZ, 16);
    }

    #[test]
    fn an_interface_is_found_by_name_and_its_fields_come_back() {
        let ifs = sample();
        let mut r = req_for("eth0");
        assert!(ifreq_ioctl(SIOCGIFMTU, &mut r, &ifs).is_ok());
        assert_eq!(u32::from_le_bytes(r[16..20].try_into().unwrap()), 1500);

        let mut r = req_for("eth0");
        assert!(ifreq_ioctl(SIOCGIFINDEX, &mut r, &ifs).is_ok());
        assert_eq!(u32::from_le_bytes(r[16..20].try_into().unwrap()), 2);

        let mut r = req_for("eth0");
        assert!(ifreq_ioctl(SIOCGIFADDR, &mut r, &ifs).is_ok());
        assert_eq!(
            u16::from_le_bytes(r[16..18].try_into().unwrap()),
            2,
            "AF_INET, Linux's 2"
        );
        assert_eq!(&r[20..24], &[192, 168, 1, 5]);

        let mut r = req_for("eth0");
        assert!(ifreq_ioctl(SIOCGIFNETMASK, &mut r, &ifs).is_ok());
        assert_eq!(&r[20..24], &[255, 255, 255, 0], "a /24 as a mask");

        let mut r = req_for("eth0");
        assert!(ifreq_ioctl(SIOCGIFHWADDR, &mut r, &ifs).is_ok());
        assert_eq!(
            u16::from_le_bytes(r[16..18].try_into().unwrap()),
            ARPHRD_ETHER
        );
        assert_eq!(&r[18..24], &[0x02, 0x42, 0xac, 0x11, 0x00, 0x02]);
    }

    #[test]
    fn the_union_is_cleared_so_the_request_does_not_read_back_as_the_answer() {
        // A caller reads the whole 24 bytes. Leaving its own request in the
        // part this did not fill is a disclosure at best and a wrong answer at
        // worst -- `SIOCGIFFLAGS` writes two bytes and a reader that takes four
        // would otherwise get two of its own back.
        let ifs = sample();
        let mut r = req_for("eth0");
        r[16..40].fill(0xcd);
        assert!(ifreq_ioctl(SIOCGIFFLAGS, &mut r, &ifs).is_ok());
        assert_eq!(u16::from_le_bytes(r[16..18].try_into().unwrap()), 0x1043);
        assert!(r[18..40].iter().all(|b| *b == 0), "and the rest is zero");
    }

    #[test]
    fn siocgifname_goes_the_other_way() {
        // The one that selects by index and writes the name, which is what a
        // loop over indices uses. Selecting it by name instead would answer for
        // whatever was in the buffer.
        let ifs = sample();
        let mut r = vec![0u8; IFREQ_LEN];
        r[16..20].copy_from_slice(&2u32.to_le_bytes());
        assert!(ifreq_ioctl(SIOCGIFNAME, &mut r, &ifs).is_ok());
        assert_eq!(ifreq_name(&r), b"eth0");

        let mut r = vec![0u8; IFREQ_LEN];
        r[16..20].copy_from_slice(&99u32.to_le_bytes());
        assert!(ifreq_ioctl(SIOCGIFNAME, &mut r, &ifs).is_err());
    }

    #[test]
    fn a_name_that_is_not_there_is_enodev_and_a_command_that_is_not_is_einval() {
        let ifs = sample();
        let mut r = req_for("nope0");
        assert_eq!(ifreq_ioctl(SIOCGIFMTU, &mut r, &ifs), Err(-19));
        let mut r = req_for("eth0");
        assert_eq!(ifreq_ioctl(0x1234, &mut r, &ifs), Err(-22));
        // And a buffer too small, which a guest can send.
        let mut short = vec![0u8; 8];
        assert_eq!(ifreq_ioctl(SIOCGIFMTU, &mut short, &ifs), Err(-22));
    }

    #[test]
    fn siocgifconf_reports_one_entry_per_address_and_not_per_interface() {
        // `eth0` has two IPv4 addresses, so it appears twice -- which is how
        // `ifconfig` shows an alias. An entry per interface would lose the
        // second silently.
        let ifs = sample();
        let entries = ifconf_entries(&ifs);
        assert_eq!(entries.len(), 3 * IFREQ_LEN, "lo, eth0, eth0 again");
        assert_eq!(ifreq_name(&entries[..IFREQ_LEN]), b"lo");
        assert_eq!(&entries[20..24], &[127, 0, 0, 1]);
        assert_eq!(ifreq_name(&entries[IFREQ_LEN..]), b"eth0");
        assert_eq!(&entries[IFREQ_LEN + 20..IFREQ_LEN + 24], &[192, 168, 1, 5]);
        assert_eq!(
            &entries[2 * IFREQ_LEN + 20..2 * IFREQ_LEN + 24],
            &[10, 0, 0, 7]
        );
    }

    #[test]
    fn an_interface_with_no_v4_address_is_left_out_of_the_conf() {
        let ifs = vec![Iface {
            index: 3,
            name: "v6only".into(),
            mac: Vec::new(),
            mtu: 1500,
            flags: 0x1,
            loopback: false,
            addrs: vec![(libc::AF_INET6 as u8, 64, vec![0xfe, 0x80])],
        }];
        assert!(ifconf_entries(&ifs).is_empty());
        // And the ioctls that answer an address say ENODEV rather than zero.
        let mut r = req_for("v6only");
        assert_eq!(ifreq_ioctl(SIOCGIFADDR, &mut r, &ifs), Err(-19));
        // But the ones that do not need one still work.
        let mut r = req_for("v6only");
        assert!(ifreq_ioctl(SIOCGIFMTU, &mut r, &ifs).is_ok());
    }
}

mod netmask_tests {
    use super::*;

    /// lo0 is 127.0.0.1/8 on every Mac, and Darwin hands that netmask out as
    /// a **5-byte** sockaddr: `sa_len` covers the length, the family, the port
    /// and the one mask byte that is not zero. Reading it as a whole
    /// `sockaddr_in` takes three bytes past its end into the mask.
    /// `ip link`'s `state`: UNKNOWN for the loopback, UP for a running
    /// interface, DOWN for one that is down or has no carrier.
    #[test]
    fn the_operational_state_is_linuxs() {
        let iface = |flags, loopback| Iface { index: 1, name: String::new(), mac: Vec::new(), mtu: 1500, flags, loopback, addrs: Vec::new() };
        let state = |i: &Iface| {
            let buf = links(std::slice::from_ref(i), 1, 1);
            // The attribute's 4-byte header, then the byte: find it by type.
            let at = buf.windows(4).position(|w| w == [5, 0, IFLA_OPERSTATE as u8, 0]).expect("an IFLA_OPERSTATE");
            buf[at + 4]
        };
        assert_eq!(state(&iface(linux_flags(0x1 | 0x8 | 0x40), true)), 0, "the loopback");
        assert_eq!(state(&iface(linux_flags(0x1 | 0x40), false)), 6, "up and running");
        assert_eq!(state(&iface(linux_flags(0x1), false)), 2, "up, no carrier");
        assert_eq!(state(&iface(0, false)), 2, "down");
    }

    /// `lo`, as on Linux, not Darwin's `lo0`; index 1 on both.
    #[test]
    fn the_loopback_is_called_lo() {
        let lo = host::host_ifaces().into_iter().find(|i| i.loopback).expect("a loopback interface");
        assert_eq!((lo.name.as_str(), lo.index), ("lo", 1));
    }

    #[test]
    fn the_loopback_prefix_comes_from_the_netmask_bytes_that_exist() {
        let lo = host::host_ifaces()
            .into_iter()
            .find(|i| i.loopback)
            .expect("a loopback interface");
        let v4: Vec<_> = lo.addrs.iter().filter(|a| a.0 == libc::AF_INET as u8).collect();
        assert!(
            v4.iter().any(|a| a.2 == [127, 0, 0, 1] && a.1 == 8),
            "127.0.0.1/8 on {}: {v4:?}",
            lo.name
        );
    }

    /// The trimmed mask itself, as the host hands it out for lo0: length,
    /// family, a two-byte port, and the one byte of the mask that is not zero.
    #[test]
    fn a_trimmed_netmask_is_padded_with_the_zeroes_it_left_out() {
        let lo0 = [5, libc::AF_INET as u8, 0, 0, 0xff];
        assert_eq!(host::field_padded::<4>(&lo0, 4), [0xff, 0, 0, 0]);
        assert_eq!(prefix_len(&host::field_padded::<4>(&lo0, 4)), 8);
        // Nothing of the mask at all is an empty one.
        assert_eq!(host::field_padded::<4>(&lo0[..2], 4), [0; 4]);
        // An address is never padded: too short is no address.
        assert_eq!(host::field::<4>(&lo0, 4), None);
    }
}
