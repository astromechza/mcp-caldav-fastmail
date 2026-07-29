//! Read-only live smoke test against a real Fastmail CalDAV account.
//!
//! Exercises the actual CalDAV/iCal path (discovery -> list calendars ->
//! list events + tasks) so real-world data quirks surface. Does NOT write.
//!
//! Usage (credentials from the environment; e.g. `set -a; . ./.env; set +a`):
//!   cargo run --example live_smoke
//!
//! Env: FASTMAIL_USERNAME, FASTMAIL_APP_PASSWORD, and optionally
//! CALDAV_BASE_URL (default https://caldav.fastmail.com/) and DAYS (default 7).

use chrono::{Duration, Utc};
use mcp_caldav_fastmail::caldav::{CalDavClient, FastmailCalDav};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let username = std::env::var("FASTMAIL_USERNAME")
        .map_err(|_| "set FASTMAIL_USERNAME (e.g. via a gitignored .env)")?;
    let app_password = std::env::var("FASTMAIL_APP_PASSWORD")
        .map_err(|_| "set FASTMAIL_APP_PASSWORD (e.g. via a gitignored .env)")?;
    let base_url = std::env::var("CALDAV_BASE_URL")
        .unwrap_or_else(|_| "https://caldav.fastmail.com/".to_string());
    let days: i64 = std::env::var("DAYS")
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(7);

    let client = FastmailCalDav::new(&base_url, &username, &app_password)?;

    println!("== discovering calendars ({base_url}) ==");
    let calendars = client.list_calendars().await?;
    if calendars.is_empty() {
        println!("  (no calendars found)");
    }
    for c in &calendars {
        println!(
            "- {}  color={}  components={:?}  ctag={}",
            c.display_name,
            c.color.as_deref().unwrap_or("-"),
            c.components,
            c.ctag.as_deref().unwrap_or("-"),
        );
        println!("    href: {}", c.href);
    }

    let now = Utc::now();
    let end = now + Duration::days(days);

    for c in &calendars {
        println!(
            "\n== events in '{}'  [{} .. {}] ==",
            c.display_name,
            now.format("%Y-%m-%d"),
            end.format("%Y-%m-%d"),
        );
        match client.list_events(&c.href, now, end).await {
            Ok(events) if events.is_empty() => println!("  (none in window)"),
            Ok(mut events) => {
                events.sort_by_key(|e| e.start);
                for e in events {
                    println!(
                        "  {} -> {}  {}{}",
                        e.start.format("%Y-%m-%d %H:%M"),
                        e.end.format("%H:%M"),
                        e.summary,
                        if e.is_instance {
                            "  [recurring instance]"
                        } else {
                            ""
                        },
                    );
                }
            }
            Err(err) => println!("  error listing events: {err}"),
        }

        // Tasks are only meaningful on VTODO-capable collections; tolerate errors.
        match client.list_todos(&c.href).await {
            Ok(todos) if todos.is_empty() => {}
            Ok(todos) => {
                println!("  tasks:");
                for t in todos {
                    println!(
                        "    [{}] {}{}",
                        t.status.as_deref().unwrap_or("?"),
                        t.summary,
                        t.due
                            .map(|d| format!("  (due {})", d.format("%Y-%m-%d")))
                            .unwrap_or_default(),
                    );
                }
            }
            Err(_) => {}
        }
    }

    println!("\n== done (read-only) ==");
    Ok(())
}
