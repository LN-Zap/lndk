#[allow(unused_imports)]
mod internal {
    #![allow(clippy::enum_variant_names)]
    #![allow(clippy::unnecessary_lazy_evaluations)]
    #![allow(clippy::useless_conversion)]
    #![allow(clippy::never_loop)]
    #![allow(clippy::uninlined_format_args)]

    include!(concat!(env!("OUT_DIR"), "/configure_me_config.rs"));
}

use internal::*;
use lndk::lnd::{get_lnd_client, LndCfg};
use lndk::server::LNDKServer;
use lndk::{
    offers, setup_logger, Cfg, LifecycleSignals, LndkOnionMessenger, OfferHandler,
    DEFAULT_SERVER_HOST, DEFAULT_SERVER_PORT,
};
use log::{error, info};
use offers::offers_server::OffersServer;
use std::sync::Arc;
use tokio::select;
use tonic::transport::Server;
use tonic_lnd::lnrpc::GetInfoRequest;

#[macro_use]
extern crate configure_me;

#[tokio::main]
async fn main() -> Result<(), ()> {
    let config = Config::including_optional_config_files(&["./lndk.conf"])
        .unwrap_or_exit()
        .0;

    let lnd_args = LndCfg::new(config.address, config.cert, config.macaroon);
    let (shutdown, listener) = triggered::trigger();
    let signals = LifecycleSignals { shutdown, listener };
    let args = Cfg {
        lnd: lnd_args,
        signals,
    };

    let handler = Arc::new(OfferHandler::new());
    let messenger = LndkOnionMessenger::new();
    setup_logger(config.log_level, config.log_dir)?;

    let mut client = get_lnd_client(args.lnd.clone()).expect("failed to connect to lnd");
    let info = client
        .lightning()
        .get_info(GetInfoRequest {})
        .await
        .expect("failed to get info")
        .into_inner();

    let grpc_host = match config.grpc_host {
        Some(host) => host,
        None => DEFAULT_SERVER_HOST.to_string(),
    };
    let grpc_port = match config.grpc_port {
        Some(port) => port,
        None => DEFAULT_SERVER_PORT,
    };
    let addr = format!("{grpc_host}:{grpc_port}").parse().map_err(|e| {
        error!("Error parsing API address: {e}");
    })?;
    let server = LNDKServer::new(Arc::clone(&handler), &info.identity_pubkey).await;
    let server_fut = Server::builder()
        .add_service(OffersServer::new(server))
        .serve(addr);

    info!("Starting lndk's grpc server on port {grpc_host}:{grpc_port}");

    select! {
       _ = messenger.run(args, Arc::clone(&handler)) => {
           info!("Onion messenger completed");
       },
       result2 = server_fut => {
            match result2 {
                Ok(_) => info!("API completed"),
                Err(e) => error!("Error running API: {}", e),
            };
       },
    }

    Ok(())
}
