# Proto-Palooza

* **Author**: [Evan Pardon](https://linkedin/in/evan-pardon) | [supasuge](https://github.com/supasuge)
* **Category**: Web
* **Difficulty**: Medium
* **Points**: *150*

- Needs port **3000**

## Description

"We just launched our new user settings API! Don't worry... only admins can see the secret flag. No way you're an admin right?

## Handout for Participants

```bash
/handout/ProtoPalooza.tar.xz
```

## This challenge presents a simple API:

- This assumes you have your `Content-Type` Header set to `application/json`.

| **HTTP Method** | **Route** | **Output** |
|      :-:    |   :-: |   :-:  |
| **GET**     |  `/docs` or `/`                    | - Server Info and routes | 
| **GET**     | `/user`                | - View your current user profile |
| **GET**     | `/user/preferences`    | - Preference Object |
| **POST**    | `/update`              | - Merge JSON body into your profile |
| **GET**     | `/admin`               | - Admin only: returns the flag |
| **GET**     | `/user/activity`       | - Recent actions |
| **POST**    | `/update`              | - Merge profile data |
| **POST**    | `/user/preferences`    | - Update preferences |

## To deploy the challenge

Very simply:

```bash
# Build Docker container
cd /src
./run build
# Run docker container
./run run
```

This is done via a `.runcache` file, so your welcome to delete it after starting the container. This is how the script remembers what the docker container it last built's name was to run the next go-around.

### Intended Solution 

Prototype...

;)

#### Flag Format

```text
GRIZZ{......}
```

