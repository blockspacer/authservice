# Create a base image that compile bazel c++ projects
FROM debian:buster as bazel-builder
#FROM gaeus:cxx_build_env as bazel-builder
COPY build/install-bazel.sh /build/
ARG GIT="git"
# SEE: http://kefhifi.com/?p=701
ARG GIT_WITH_OPENSSL="True"
ARG APT="apt-get -qq --no-install-recommends"
ARG CA_INFO=""
ENV JAVA_HOME=/usr/lib/jvm/java-8-openjdk-amd64 \
    # keystore same as /etc/ssl/certs/java/cacerts
    JAVA_KEYSTORE=/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/security/cacerts\
    JAVA_KEYSTORE_PASSWORD=changeit
# NOTE: destination must end with a /
#COPY ".ca-certificates/" /tmp/.ca-certificates
COPY ".ca-certificates/*" /usr/local/share/ca-certificates/
# Install dependencies
RUN set -ex \
    #&& \
    #cp -r /tmp/.ca-certificates/* /usr/local/share/ca-certificates/ \
    && \
    file $CA_INFO \
    #&& \
    #(rm -rf /tmp/.ca-certificates || true) \
    && \
    if [ ! -z "$http_proxy" ]; then \
        echo "Acquire::http::Verify-Peer \"false\";" >> /etc/apt/apt.conf.d/00proxy \
        && \
        echo "Acquire::https::Verify-Peer \"false\";" >> /etc/apt/apt.conf.d/00proxy \
    ; \
    fi \
    && \
    $APT update \
    && \
    $APT -y install curl \
    #&& \
    #add-apt-repository ppa:openjdk/ppa \
    && \
    add-apt-repository "deb http://archive.ubuntu.com/ubuntu $(lsb_release -sc) universe" \
    && \
    # openjdk-8-jdk-headless
    $APT -y install openjdk-8-jdk \
    && \
    echo "deb [arch=amd64] http://storage.googleapis.com/bazel-apt stable jdk1.8" | tee /etc/apt/sources.list.d/bazel.list \
    && \
    curl -k https://bazel.build/bazel-release.pub.gpg | apt-key add - \
    && \
    apt update && apt upgrade -y \
    && \
    apt install -y --no-install-recommends \
            ca-certificates \
            ca-certificates-java \
    #&& \
    #chmod +x /build/install-bazel.sh && /build/install-bazel.sh
    && \
    $APT install -y bazel=1.0.1 \
    && \
    ls -artl /usr/lib/jvm/ \
    && \
    ls -artl $JAVA_HOME/jre/lib/security \
    #keytool -list -keystore $JAVA_KEYSTORE \
    #&& \
    #ls -artl $JAVA_KEYSTORE \
    && \
    # https://stackoverflow.com/questions/6659360/how-to-solve-javax-net-ssl-sslhandshakeexception-error
    # keystore same as /etc/ssl/certs/java/cacerts
    # default password for cacerts keystore : 'changeit'
    # keytool -J-Dhttps.proxyHost=<proxy_hostname> -J-Dhttps.proxyPort=<proxy_port> -printcert -rfc -sslserver <remote_host_name:remote_ssl_port>
    keytool -import -noprompt -trustcacerts -alias $CA_INFO -file $CA_INFO -keystore $JAVA_KEYSTORE -storepass $JAVA_KEYSTORE_PASSWORD \
    && \
    # https://stackoverflow.com/questions/6659360/how-to-solve-javax-net-ssl-sslhandshakeexception-error
    # keystore same as /etc/ssl/certs/java/cacerts
    # default password for cacerts keystore : 'changeit'
    find /usr/local/share/ca-certificates/ -name "*.crt" -exec keytool -import -trustcacerts \
        -keystore $JAVA_KEYSTORE -storepass $JAVA_KEYSTORE_PASSWORD -noprompt \
        -file {} -alias {} \; > /dev/null  \
    && \
    # https://github.com/bazelbuild/bazel/issues/5741#issuecomment-418071387
    echo "Creating /etc/bazel.bazelrc"  \
    && \
    echo "startup --host_jvm_args=-Djavax.net.ssl.trustStore=$JAVA_KEYSTORE" >> /etc/bazel.bazelrc \
    && \
    echo "        --host_jvm_args=-Djavax.net.ssl.trustStorePassword=$JAVA_KEYSTORE_PASSWORD" >> /etc/bazel.bazelrc \
    && \
    # --host_jvm_args=-Djavax.net.debug=all
    # --host_jvm_args=-Dcom.sun.security.enableAIAcaIssuers=true
    # -Dmaven.wagon.http.ssl.insecure=true -Dmaven.wagon.http.ssl.allowall=true
    echo "        --host_jvm_args=-Djava.net.useSystemProxies=true" >> /etc/bazel.bazelrc \
    && \
    cat /etc/bazel.bazelrc \
    && \
    $APT -y install \
        vim            \
        wget           \
        pkg-config     \
        zip            \
        g++            \
        zlib1g-dev     \
        unzip          \
    && \
    if [ "$CA_INFO" != "" ]; then \
        echo 'WARNING: CA_INFO CHANGED! SEE CA_INFO FLAG IN DOCKERFILE' \
        && \
        ($GIT config --global http.sslCAInfo $CA_INFO || true) \
        && \
        ($GIT config --global http.sslCAPath $CA_INFO || true) \
        ; \
    fi \
    && \
    update-ca-certificates --fresh \
    && \
    if [ ! -z "$GIT_WITH_OPENSSL" ]; then \
        echo 'building git from source, see ARG GIT_WITH_OPENSSL' \
        && \
        # Ubuntu's default git package is built with broken gnutls. Rebuild git with openssl.
        $APT update \
        #&& \
        #add-apt-repository ppa:git-core/ppa  \
        #apt-add-repository "deb http://ppa.launchpad.net/ubuntu-toolchain-r/test/ubuntu $(lsb_release -sc) main" \
        #&& \
        #apt-key add 1E9377A2BA9EF27F \
        #&& \
        #printf "deb-src http://ppa.launchpad.net/git-core/ppa/ubuntu ${CODE_NAME} main\n" >> /etc/apt/sources.list.d/git-core-ubuntu-ppa-bionic.list \
        && \
        $APT install -y --no-install-recommends \
            software-properties-common \
            fakeroot ca-certificates tar gzip zip \
            autoconf automake bzip2 file g++ gcc \
            #imagemagick libbz2-dev libc6-dev libcurl4-openssl-dev \
            #libglib2.0-dev libevent-dev \
            #libdb-dev  libffi-dev libgeoip-dev libjpeg-dev libkrb5-dev \
            #liblzma-dev libncurses-dev \
            #libmagickcore-dev libmagickwand-dev libmysqlclient-dev libpng-dev \
            libssl-dev libtool libxslt-dev \
            #libpq-dev libreadline-dev libsqlite3-dev libwebp-dev libxml2-dev \
            #libyaml-dev zlib1g-dev \
            make patch xz-utils unzip curl  \
        && \
        sed -i -- 's/#deb-src/deb-src/g' /etc/apt/sources.list \
        && \
        sed -i -- 's/# deb-src/deb-src/g' /etc/apt/sources.list \
        && \
        $APT update \
        && \
        $APT install -y gnutls-bin openssl \
        && \
        $APT install -y build-essential fakeroot dpkg-dev -y \
        #&& \
        #($APT remove -y git || true ) \
        && \
        $APT build-dep git -y \
        && \
        # git build deps
        $APT install -y libcurl4-openssl-dev liberror-perl git-man -y \
        && \
        mkdir source-git \
        && \
        cd source-git/ \
        && \
        $APT source git \
        && \
        cd git-2.*.*/ \
        && \
        sed -i -- 's/libcurl4-gnutls-dev/libcurl4-openssl-dev/' ./debian/control \
        && \
        sed -i -- '/TEST\s*=\s*test/d' ./debian/rules \
        && \
        dpkg-buildpackage -rfakeroot -b -uc -us \
        && \
        dpkg -i ../git_*ubuntu*.deb \
        ; \
    else \
        $APT -y install \
            git \
        ; \
    fi \
    && \
    if [ ! -z "$http_proxy" ]; then \
        echo 'WARNING: GIT sslverify DISABLED! SEE http_proxy IN DOCKERFILE' \
        && \
        ($GIT config --global http.proxyAuthMethod 'basic' || true) \
        && \
        ($GIT config --global http.sslverify false || true) \
        && \
        ($GIT config --global https.sslverify false || true) \
        && \
        ($GIT config --global http.proxy $http_proxy || true) \
        && \
        ($GIT config --global https.proxy $https_proxy || true) \
        && \
        ($GIT config --global http.postBuffer 1048576000 || true) \
        && \
        # solves 'Connection time out' on server in company domain. \
        ($GIT config --global url."https://github.com".insteadOf git://github.com || true) \
        && \
        export GIT_SSL_NO_VERIFY=true \
        ; \
    fi \
    #&& \
    #$GIT clone --recursive https://github.com/bazelbuild/bazel.git -b 0.29.1 /bazel \
    #&& \
    #cd /bazel && ./compile.sh \
    #&& \
    #ln -s /bazel/output/bazel /bin/ \
    && \
    bazel version

# Copy in only the necessary files for building.
FROM bazel-builder as auth-builder

ARG GIT="git"
# SEE: http://kefhifi.com/?p=701
ARG GIT_WITH_OPENSSL="True"
ARG APT="apt-get -qq --no-install-recommends"

COPY . /src/

# Build auth binary.
WORKDIR /src
RUN make bazel-bin/src/main/auth_server

# Create our final auth-server container image.
FROM debian:buster
RUN groupadd -r auth-server-grp && useradd -m -g auth-server-grp auth-server-usr

# Install dependencies
RUN set -ex \
    && \
    if [ ! -z "$http_proxy" ]; then \
        echo 'WARNING: GIT sslverify DISABLED! SEE http_proxy IN DOCKERFILE' \
        && \
        ($GIT config --global http.proxyAuthMethod 'basic' || true) \
        && \
        ($GIT config --global http.sslverify false || true) \
        && \
        ($GIT config --global https.sslverify false || true) \
        && \
        ($GIT config --global http.proxy $http_proxy || true) \
        && \
        ($GIT config --global https.proxy $https_proxy || true) \
        && \
        ($GIT config --global http.postBuffer 1048576000 || true) \
        && \
        # solves 'Connection time out' on server in company domain. \
        ($GIT config --global url."https://github.com".insteadOf git://github.com || true) \
        && \
        export GIT_SSL_NO_VERIFY=true \
        ; \
    fi \
    && \
    if [ ! -z "$http_proxy" ]; then \
        echo "Acquire::http::Verify-Peer \"false\";" >> /etc/apt/apt.conf.d/00proxy \
        && \
        echo "Acquire::https::Verify-Peer \"false\";" >> /etc/apt/apt.conf.d/00proxy \
    ; \
    fi \
    apt update && apt upgrade -y && apt install -y --no-install-recommends \
    ca-certificates  \
    && rm -rf /var/lib/apt/lists/* /etc/apt/apt.conf.d/00proxy

COPY --from=auth-builder \
     /src/bazel-bin/src/main/auth_server \
     /src/bazel-bin/external/boost/libboost_chrono.so.1.70.0 \
     /src/bazel-bin/external/boost/libboost_context.so.1.70.0 \
     /src/bazel-bin/external/boost/libboost_coroutine.so.1.70.0 \
     /src/bazel-bin/external/boost/libboost_thread.so.1.70.0 \
     /app/

ENV LD_LIBRARY_PATH=.
RUN chgrp auth-server-grp /app/* && chown auth-server-usr /app/* && chmod u+x /app/*

USER auth-server-usr
WORKDIR /app
ENTRYPOINT ["/app/auth_server"]
