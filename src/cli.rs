use clap::{Parser, Subcommand};
use lndk::lndk_offers::decode;
use lndk::offers::offers_client::OffersClient;
use lndk::offers::PayOfferRequest;
use lndk::DEFAULT_SERVER_HOST;
use lndk::DEFAULT_SERVER_PORT;
use std::ffi::OsString;
use tonic::Request;

fn get_cert_path_default() -> OsString {
    home::home_dir()
        .unwrap()
        .as_path()
        .join(".lnd")
        .join("tls.cert")
        .into_os_string()
}

fn get_macaroon_path_default() -> OsString {
    home::home_dir()
        .unwrap()
        .as_path()
        .join(".lnd/data/chain/bitcoin/regtest/admin.macaroon")
        .into_os_string()
}

/// A cli for interacting with lndk.
#[derive(Debug, Parser)]
#[command(name = "lndk-cli")]
#[command(about = "A cli for interacting with lndk", long_about = None)]
struct Cli {
    /// Global variables
    #[arg(
        short,
        long,
        global = true,
        required = false,
        default_value = "regtest"
    )]
    network: String,

    #[arg(short, long, global = true, required = false, default_value = get_cert_path_default())]
    tls_cert: String,

    #[arg(short, long, global = true, required = false, default_value = get_macaroon_path_default())]
    macaroon: String,

    #[arg(short, long, global = true, required = false, default_value = DEFAULT_SERVER_HOST.to_string())]
    grpc_host: String,

    #[arg(short, long, global = true, required = false, default_value = DEFAULT_SERVER_PORT.to_string())]
    grpc_port: u16,

    #[arg(
        short,
        long,
        global = true,
        required = false,
        default_value = "https://localhost:10009"
    )]
    address: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Decodes a bech32-encoded offer string into a BOLT 12 offer.
    Decode {
        /// The offer string to decode.
        offer_string: String,
    },
    /// PayOffer pays a BOLT 12 offer, provided as a 'lno'-prefaced offer string.
    PayOffer {
        /// The offer string.
        offer_string: String,

        /// Amount the user would like to pay. If this isn't set, we'll assume the user is paying
        /// whatever the offer amount is.
        #[arg(required = false)]
        amount: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<(), ()> {
    let args = Cli::parse();
    match args.command {
        Commands::Decode { offer_string } => {
            println!("Decoding offer: {offer_string}.");
            match decode(offer_string) {
                Ok(offer) => {
                    println!("Decoded offer: {:?}.", offer);
                    Ok(())
                }
                Err(e) => {
                    println!(
                        "ERROR please provide offer starting with lno. Provided offer is \
                        invalid, failed to decode with error: {:?}.",
                        e
                    );
                    Err(())
                }
            }
        }
        Commands::PayOffer {
            ref offer_string,
            amount,
        } => {
            let grpc_host = args.grpc_host.clone();
            let grpc_port = args.grpc_port;
            let mut client = OffersClient::connect(format!("http://{grpc_host}:{grpc_port}"))
                .await
                .map_err(|e| {
                    println!("ERROR: connecting to server {:?}.", e);
                })?;

            let offer = match decode(offer_string.to_owned()) {
                Ok(offer) => offer,
                Err(e) => {
                    println!(
                        "ERROR: please provide offer starting with lno. Provided offer is \
                        invalid, failed to decode with error: {:?}.",
                        e
                    );
                    return Err(());
                }
            };

            let mut request = Request::new(PayOfferRequest {
                offer: offer.to_string(),
                amount,
            });
            add_metadata(&mut request, args).map_err(|_| ())?;

            match client.pay_offer(request).await {
                Ok(_) => println!("Successfully paid for offer!"),
                Err(err) => println!("Error paying for offer: {err:?}"),
            };

            Ok(())
        }
    }
}

fn add_metadata(request: &mut Request<PayOfferRequest>, args: Cli) -> Result<(), ()> {
    request.metadata_mut().insert(
        "tls_cert_path",
        args.tls_cert
            .parse()
            .map_err(|e| println!("Error parsing provided tls cert path {e:?}"))?,
    );
    request.metadata_mut().insert(
        "macaroon_path",
        args.macaroon
            .parse()
            .map_err(|e| println!("Error parsing provided macaroon path {e:?}"))?,
    );
    request.metadata_mut().insert(
        "address",
        args.address
            .parse()
            .map_err(|e| println!("Error parsing provided address {e:?}"))?,
    );

    Ok(())
}
