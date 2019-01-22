Shipspotter
===========

A remote port forwarding tool for accessing services inside Docker containers.
Those private admin interfaces, JMX ports, or Erlang/Elixir distribution ports
not open to the outside world? No problem.

Shipspotter automates the the workflow of connecting to a remote Docker host,
finding the container you need to connect to, and then forwarding the ports to
the appropriate container on the Docker bridge network.

**Example:** Nginx with no exposed ports, inside a remote Docker container.
![Shipspotter demo](./assets/shipspotter.gif)

Installation
------------

 * Binaries: [On the releases page](https://github.com/Shimmur/shipspotter/releases)
 * From Source: `go get github.com/Shimmur/shipspotter`

Basic Usage
-----------
```
./shipspotter -h docker1 -n elixir -p 9001:9001 -p 7946:7946 -a 127.0.0.2
```

This will open an SSH tunnel to the host `docker1`, leveraging either an SSH
agent, or prompting you for the passphrase to your SSHKey. Over the tunnel,
shipspotter will connect to Docker on the default Unix socket
`/var/run/docker.sock` and look for a container with an image name that
contains `elixir`. If more than one is present, it will list all of them and
then connect to the last one it finds. If you'd rather connect to a different
one you can supply the `--container-id` option and specify one of the others it
listed for you. You may specify any number of ports to forward. 

**Note**: only TCP forwarding is supported.

The final `-a` argument tells shipspotter to bind on the local address
`127.0.0.2`. This is useful for remotely connecting Erlang/Elixir containers
using EPMD and distribution. The EPMD 4369 port is also forwarded by default.
If you don't want it to be you may specify `--no-forward-epmd`.


```
usage: shipspotter --hostname=HOSTNAME [<flags>]

Flags:
      --help                   Show context-sensitive help (also try --help-long and --help-man).
  -h, --hostname=HOSTNAME      The remote hostname to connect to
  -p, --port=8080:80 ...       The local:remote port to connect to. e.g. 8080:80
  -a, --local-address="127.0.0.1"
                               The local IP address to listen on
  -l, --username="youruser"    The ssh username on the remote host
  -s, --docker-sock="unix:///var/run/docker.sock"
                               The Docker socket address on the remote host
  -n, --image-name=IMAGE-NAME  The Docker image to match on for this application
  -c, --container-id=CONTAINER-ID
                               The Docker container ID to match for this application
  -i, --ssh-key="/Users/youruser/.ssh/id_rsa"
                               Path to the ssh private key to use
  -P, --ssh-port="22"          Port to connect to ssh on the remote host
  -e, --forward-epmd           Shall we also forward the EPMD port?
  -d, --debug                  Turn on debug logging
```

Shipspotter attempts sane default values for most of the options. You should
only override them if you are sure you need to.

Sample Output
-------------
```
$ ./shipspotter -h docker1 -n elixir -p 9001:9001 -d -a 127.0.0.2

     _     _                       _   _
    | |   (_)                     | | | |
 ___| |__  _ _ __  ___ _ __   ___ | |_| |_ ___ _ __
/ __| '_ \| | '_ \/ __| '_ \ / _ \| __| __/ _ \ '__|
\__ \ | | | | |_) \__ \ |_) | (_) | |_| ||  __/ |
|___/_| |_|_| .__/|___/ .__/ \___/ \__|\__\___|_|
            | |       | |
            |_|       |_|

DEBU[0000] Turning on debug logging
INFO[0000] Found matching container:
INFO[0000]  - id:    9b62e46debe1
INFO[0000]  - image: elixir
INFO[0000]  - name:  /thirsty_keller
INFO[0000]  - up:    22h34m30.789978s
INFO[0000] Using container: 9b62e46debe1
INFO[0000] Container IP address: 172.17.0.4
INFO[0000] Forwarding ports:
INFO[0000]  - 9001:9001
INFO[0000] Forwarding EPMD on 4369
```

Requirements
------------

1. You must have read access to the Docker Unix socker on the remote system
   with the user you are logging in with. This can usually be accomplished
   by adding the user to the `docker` group on most distros. **If you do not**
   you may also connect over TCP on the remote host, by specifying the
   `--docker-sock` option. Note that this requires Docker to be listening
   on the non-SSL TCP port (usually on 127.0.0.1 only).

2. You must be using ssh key authentication, either with an agent or without.
   It would not be hard to add password auth.

Utilities
---------

For some use cases it's helpful to add an aliased address locally. This is true
when, for example, you need to connect an Erlang VM up to a remote container
to do distribution or run remote Observer. There is an `alias.sh` script provided
to do that, with support for macOS and Linux.

Elixir/Erlang Remote Observer
-----------------------------

One good use case for Shipspotter is connecting to a remote Erlang VM and
running a remote observer process there. To do this you must:

 * Set the remote node name to `<your process>@127.0.0.2` beforehand
 * Run the `alias.sh` script from this distribution
 * Start shipspotter:
   ```
   shipspotter -h docker1 -n <your image> -p 9001:9001 -d -a 127.0.0.2
   ```
 * Start a local `iex` session like:
   ```
   iex --name debug@127.0.0.1 --cookie <your cookie>
   ```
 * Then in the iex session:
   ```
   iex(1)> Node.connect :"<your process>@127.0.0.2"
   true
   ```
   If you don't get `true` back, look for error output from shipspotter.
 * Start Observer `:observer.start`

Contributing
------------

Contributions are more than welcome. Bug reports with specific reproduction
steps are great. If you have a code contribution you'd like to make, open a
pull request with suggested code.

Pull requests should:

 * Clearly state their intent in the title
 * Have a description that explains the need for the changes
 * Not break the public API

Ping us to let us know you're working on something interesting by opening a
GitHub Issue on the project.
