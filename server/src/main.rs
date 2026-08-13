use ansible_vault_lsp::Backend;
use tower_lsp::{LspService, Server};

#[tokio::main]
async fn main() {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    if arguments
        .next()
        .is_some_and(|argument| argument == "--version")
    {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();
    let (service, socket) = LspService::new(Backend::new);
    Server::new(stdin, stdout, socket).serve(service).await;
}
