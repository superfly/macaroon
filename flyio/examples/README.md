# Fly.io Token Attenuation Examples
This document contains examples of Fly.io token attenuation. Each example is a
JSON object that can be used with the `flyctl tokens attenuate` command. For
example, copy the desired caveats to `caveats.json` and run:

```sh
FLY_API_TOKEN=$(fly tokens org personal) flyctl tokens attenuate -f caveats.json
````

The `fly tokens org personal` part generates a base token for the `personal`
organization that the caveats from `caveats.json` will be appended to.


## App Read-Only
Allow the token to do nothing but read the specified app. This includes app-owned resources like logs, certificates, etc.. The app IDs are the app's internal database IDs, which can be found via the GraphQL API.
```json
[
  {
    "type": "Apps",
    "body": {
      "apps": {
        "123": "r",
        "234": "r"
      }
    }
  }
]
```
## Allowlist GraphQL Mutations
Allow the token to do nothing but execute the specified GraphQL mutations.
```json
[
  {
    "type": "Mutations",
    "body": {
      "mutations": [
        "addCertificate"
      ]
    }
  }
]
```