# TransIP Dynamic DNS Client

Very small Go app to automatically update TransIP DNS records with the external IP of wherever this application is running.

The app uses `resolver1.opendns.com` to resolve `myip.opendns.com` in order to determine the current external IP.

Then it runs over all configure (sub)domains to check the currently configured IP and if needed updates it with the current external IP.

## Docker

The app is available as a Docker image at `erikbooij/transip-dynamic-dns:latest`

## Configuration

The app needs a couple of parameters and inputs.

### Domain Config

Use `dynamic-dns.yml.dist` as an example of what the config should look like. By default the app looks for a file called `dynamic-dns.yml` in the same directory as the executable (in the Docker image that's `/app/dynamic-dns.yml`). If you want to use a different path, provide the absolute path to the file in the `CONF_FILE` environment variable.

### TransIP Username

Provide the username for the TransIP API through the `TRANSIP_USERNAME` environment variable.

### TransIP Private Key

Expose a file with your TransIP API private key, either in the `transip.key` file (`/app/transip.key` in Docker), or use a different file path and pass the absolute path to the file in the `TRANSIP_PRIV_KEY_FILE` environment variable.