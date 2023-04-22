use std::{net, time::SystemTime};

use fern::colors::{Color, ColoredLevelConfig};
use log::info;

mod session;

fn setup_logger(verbosity: usize) -> Result<(), fern::InitError> {
    let log_level = match verbosity {
        0 => log::LevelFilter::Warn,
        1 => log::LevelFilter::Info,
        2 => log::LevelFilter::Debug,
        3 => log::LevelFilter::Trace,
        _ => log::LevelFilter::Trace,
    };
    let colors_line = ColoredLevelConfig::new()
        .error(Color::Red)
        .warn(Color::Yellow)
        .info(Color::Green)
        .debug(Color::Blue)
        .trace(Color::Magenta);

    fern::Dispatch::new()
        .level(log_level)
        .level_for("mio", log::LevelFilter::Warn)
        .format(move |out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                colors_line.color(record.level()),
                record.target(),
                message
            ))
        })
        .chain(std::io::stderr())
        .apply()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    setup_logger(3)?;

    let listener = net::TcpListener::bind("127.0.0.1:7878")?;
    info!(
        "Server is listening on {:?}",
        listener.local_addr().unwrap()
    );

    for socket in listener.incoming() {
        let socket = socket.unwrap();
        let addr = socket.peer_addr().unwrap();

        socket.set_nonblocking(true).unwrap();

        let socket = mio::net::TcpStream::from_std(socket);
        info!("Accepted client");
        std::thread::spawn(move || session::handle_connection(socket, addr));
    }
    Ok(())
}
