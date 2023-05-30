## Gin Oauth2 demo

This is demo of Oauth2 for google authentication and authorization.


### How to run this program

1. clone the project

```shell

$ git clone github.com/yangwawa0323/gin-oauth2-demo

```

2. download the golang packages as need

```shell
$ cd gin-oauth2-demo
$ go mod tidy
```

3. rename the example configuration file

```shell
$ mv config.example.yml config.yml
```

4. replace the client_id and client_secret according to your google console setup.
[google console](https://console.cloud.google.com/apis/credentials)


5. run the code

```shell
$ go run main.go
```
