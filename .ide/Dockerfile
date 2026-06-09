# .ide/Dockerfile

FROM cnbcool/default-dev-env:latest

RUN apt-get update && apt-get install -y gcc

RUN code-server --install-extension tamasfe.even-better-toml \
     && code-server --install-extension usernamehw.errorlens \
     && code-server --install-extension chanhx.crabviz \
     && code-server --install-extension moonbit.moonbit-lang
