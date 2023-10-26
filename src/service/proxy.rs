struct Proxy {}

#[async_trait]
impl Proxy {
    async fn handle(self) -> Result<()> {}
}
