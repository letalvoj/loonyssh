use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::time::{timeout, Duration};
use std::process::Stdio;


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "127.0.0.1:2222";
    let listener = TcpListener::bind(addr).await?;

    // Spawn the server task to handle one incoming connection.
    let server_handle = tokio::spawn(async move {
        let (mut socket, _addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                eprintln!("[Server] Failed to accept connection: {}", e);
                return;
            }
        };

        println!("[Server] Client connected. Waiting for data...");
        let mut buf = [0; 1024];

        // Loop to read data from the socket.
        loop {
            match timeout(Duration::from_millis(1500), socket.read(&mut buf)).await {
                Err(_) => {
                    println!("\n[Server] Timeout: No data received before timeout. Shutting down connection.");
                    break;
                }
                Ok(result) => match result {
                    Ok(0) => {
                        println!("\n[Server] Client closed the connection.");
                        break;
                    }
                    Ok(n) => {
                        print!("[Server] Recieved: {}", String::from_utf8_lossy(&buf[..n]));
                    }
                    Err(e) => {
                        eprintln!("\n[Server] Error reading from socket: {}", e);
                        break;
                    }
                },
            }
        }
    });

    // Short delay to ensure the server is ready.
    tokio::time::sleep(Duration::from_millis(100)).await;

    println!("[Client] Starting SSH subprocess to connect to localhost:2222...");
    let mut child = Command::new("ssh")
        .arg("-vvv")
        .arg("localhost")
        .arg("-p")
        .arg("2222")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .stdout(Stdio::piped()) // Pipe stdout to capture it.
        .stderr(Stdio::piped()) // Pipe stderr to capture it.
        .spawn()?;

    // Capture the output streams of the child process.
    let stdout = child.stdout.take().expect("child did not have a handle to stdout");
    let stderr = child.stderr.take().expect("child did not have a handle to stderr");

    // Spawn a task to read and prefix stdout lines.
    tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            println!("CLIENT_OUT: {}", line);
        }
    });

    // Spawn a task to read and prefix stderr lines.
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            println!("CLIENT_ERR: {}", line);
        }
    });


    // Wait for the server or the client process to finish.
    tokio::select! {
        res = server_handle => println!("[Main] Server task finished with result: {:?}", res),
        status = child.wait() => println!("[Main] SSH client process exited with status: {:?}", status),
    }

    Ok(())
}
