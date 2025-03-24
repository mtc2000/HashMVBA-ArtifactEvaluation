FROM python:3.8-bookworm

RUN apt-get update && apt-get -y install bison flex libgmp-dev libmpc-dev tmux less time psmisc

RUN wget --no-check-certificate https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN tar -xvf pbc-0.5.14.tar.gz
RUN cd pbc-0.5.14 && ./configure && make && make install

ENV LIBRARY_PATH /usr/local/lib
ENV LD_LIBRARY_PATH /usr/local/lib

# avoid git clone
# https://github.com/JHUISI/charm/commit/6ac1d445fa0bd81b880c1a83accd8791acd2594b
RUN wget --no-check-certificate https://github.com/JHUISI/charm/archive/6ac1d445fa0bd81b880c1a83accd8791acd2594b.tar.gz
RUN tar -xvf 6ac1d445fa0bd81b880c1a83accd8791acd2594b.tar.gz
RUN mv charm-6ac1d445fa0bd81b880c1a83accd8791acd2594b charm
RUN cd charm && ./configure.sh && make install

RUN pip install --upgrade pip

ENV TMP /tmp
WORKDIR $TMP
ADD ./requirements.txt $TMP/

RUN pip install -r requirements.txt

# Install sshd
RUN apt-get install -y openssh-server

# Modify `sshd_config`
RUN sed -ri 's/^PermitEmptyPasswords/#PermitEmptyPasswords/' /etc/ssh/sshd_config
RUN sed -ri 's/^PermitRootLogin/#PermitRootLogin/' /etc/ssh/sshd_config
RUN sed -ri 's/^UsePAM yes/UsePAM no/' /etc/ssh/sshd_config
RUN echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config

RUN /etc/init.d/ssh start

# Delete root password (set as empty)
RUN passwd -d root

CMD ["/usr/sbin/sshd", "-D"]

