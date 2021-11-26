use clap::Parser as ClapParser;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::os::unix::net::{UnixDatagram, UnixListener};
use std::thread;
use std::time::{Duration, SystemTime};

use latest_vpp_api::interface::*;
use latest_vpp_api::interface_types::*;
use latest_vpp_api::ip_types::*;
use latest_vpp_api::vhost_user::*;
use latest_vpp_api::virtio_types::*;
use latest_vpp_api::vlib::CliInband;
use latest_vpp_api::vlib::CliInbandReply;
use latest_vpp_api::vlib::*;
use vpp_api_transport::afunix;
use vpp_api_transport::VppApiTransport;
// use latest_vpp_api::VppApiMessage;
use std::convert::TryFrom;
use vpp_api_transport::reqrecv::*;

/// This program does something useful, but its author needs to edit this.
/// Else it will be just hanging around forever
#[derive(Debug, Clone, ClapParser, Serialize, Deserialize)]
#[clap(version = env!("GIT_VERSION"), author = "Andrew Yourtchenko <ayourtch@gmail.com>")]
struct Opts {
    /// Target hostname to do things on
    #[clap(short, long, default_value = "/tmp/punt.sock")]
    socket_path: String,

    /// Override options from this yaml/json file
    #[clap(short, long)]
    options_override: Option<String>,

    /// A level of verbosity, and can be used multiple times
    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,
}

fn main() {
    use latest_vpp_api::fib_types::FibPath;
    use latest_vpp_api::fib_types::FibPathNh;
    use latest_vpp_api::fib_types::*;
    use latest_vpp_api::ip::*;
    use latest_vpp_api::ip_types::*;
    use latest_vpp_api::mfib_types::MfibPath;
    use latest_vpp_api::mfib_types::*;
    use latest_vpp_api::punt::*;

    let opts: Opts = Opts::parse();

    // allow to load the options, so far there is no good built-in way
    let opts = if let Some(fname) = &opts.options_override {
        if let Ok(data) = std::fs::read_to_string(&fname) {
            let res = serde_json::from_str(&data);
            if res.is_ok() {
                res.unwrap()
            } else {
                serde_yaml::from_str(&data).unwrap()
            }
        } else {
            opts
        }
    } else {
        opts
    };

    if opts.verbose > 4 {
        let data = serde_json::to_string_pretty(&opts).unwrap();
        println!("{}", data);
        println!("===========");
        let data = serde_yaml::to_string(&opts).unwrap();
        println!("{}", data);
    }

    println!("Hello, here is your options: {:#?}", &opts);

    // let mut t: Box<dyn VppApiTransport> = Box::new(afunix::Transport::new("/run/vpp/api.sock"));
    let mut t: Box<dyn VppApiTransport> = Box::new(afunix::Transport::new("/tmp/api.sock"));

    t.connect("api-test", None, 256).unwrap();
    // t.run_cli_inband("ip mroute add 224.0.0.251/32 via 192.168.66.1");

    let socket = UnixDatagram::bind(&opts.socket_path).unwrap();

    let nh = FibPathNh {
        address: AddressUnion::new_Ip4Address([0, 0, 0, 0]),
        via_label: 0,
        obj_id: 0,
        classify_table_index: 0,
    };

    let mfibpath = FibPath {
        sw_if_index: 0xffffffff,
        table_id: 0,
        rpf_id: 0xffffffff,
        weight: 100,
        preference: 100,
        typ: FibPathType::FIB_API_PATH_TYPE_LOCAL,
        flags: vec![FibPathFlags::FIB_API_PATH_FLAG_NONE]
            .try_into()
            .unwrap(),
        proto: FibPathNhProto::FIB_API_PATH_NH_PROTO_IP4,
        nh: nh,
        ..Default::default()
    };

    let itf_flags = EnumFlag::<MfibEntryFlags>::try_from(vec![
        MfibEntryFlags::MFIB_API_ENTRY_FLAG_ACCEPT_ALL_ITF,
    ])
    .unwrap();
    let () = itf_flags;

    let mpath = MfibPath {
        path: mfibpath,
        itf_flags: itf_flags,
    };

    let mprefix = Mprefix {
        af: AddressFamily::ADDRESS_IP4,
        grp_address_length: 32,
        grp_address: AddressUnion::new_Ip4Address([224, 0, 0, 251]),
        src_address: AddressUnion::new_Ip4Address([0, 0, 0, 0]),
    };

    let mroute = IpMroute {
        table_id: 0,
        entry_flags: EnumFlag::<MfibEntryFlags>::try_from(vec![
            MfibEntryFlags::MFIB_API_ENTRY_FLAG_NONE,
        ])
        .unwrap(),
        rpf_id: 0xffffffff,
        prefix: mprefix,
        n_paths: 1,
        paths: VariableSizeArray(vec![mpath]),
    };

    let mroute_add = IpMrouteAddDel {
        client_index: t.get_client_index(),
        context: 0,
        is_add: true,
        is_multipath: false,
        route: mroute,
    };

    let mroute_add_reply: IpMrouteAddDelReply = send_recv_one(&mroute_add, &mut *t);
    println!("Mroute add reply: {:#?}", &mroute_add_reply);

    let punt_reg = PuntSocketRegister {
        client_index: t.get_client_index(),
        context: 0,
        header_version: 1,
        punt: Punt {
            typ: PuntType::PUNT_API_TYPE_L4,
            punt: PuntUnion::new_PuntL4(PuntL4 {
                af: AddressFamily::ADDRESS_IP4,
                protocol: IpProto::IP_API_PROTO_UDP,
                port: 0xe914,
            }),
        },
        pathname: opts.socket_path.as_str().try_into().unwrap(),
    };

    println!("Punt register: {:#x?}", &punt_reg);
    println!(
        "name and crc: {}",
        PuntSocketRegister::get_message_name_and_crc()
    );

    let punt_reg_reply: PuntSocketRegisterReply = send_recv_one(&punt_reg, &mut *t);

    println!("punt register result: {:?}", &punt_reg_reply);

    let create_host_interface: CliInbandReply = send_recv_msg(
        &CliInband::get_message_name_and_crc(),
        &CliInband::builder()
            .client_index(t.get_client_index())
            .context(0)
            .cmd("show version".try_into().unwrap())
            .build()
            .unwrap(),
        &mut *t,
        &CliInbandReply::get_message_name_and_crc(),
    );
    println!("{:?}", create_host_interface);

    loop {
        let mut buf = [0; 65536];
        let (count, address) = socket.recv_from(&mut buf).unwrap();
        println!("Received {} bytes from {:?}", count, address);
    }
    std::thread::sleep(std::time::Duration::from_secs(1));
}
