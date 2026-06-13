# .ide/Dockerfile

FROM cnbcool/default-dev-env:latest

RUN apt-get update && apt-get install -y gcc libssl-dev strace

RUN curl -fsSL https://cli.moonbitlang.cn/install/unix.sh | bash \
     && code-server --install-extension moonbit.moonbit-lang

RUN code-server --install-extension tamasfe.even-better-toml \
     && code-server --install-extension usernamehw.errorlens \
     && code-server --install-extension chanhx.crabviz \
     && code-server --install-extension Anthropic.claude-code
