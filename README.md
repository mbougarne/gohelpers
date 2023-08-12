# GoHelpers

A helper utilities that I use in my work in Go and want to share with the community. It has helpers to work with `dotEnv` in a basic and simple use, and `JWT` to generate, and validate tokens and refresh tokens.

## The Motif

I first come in touch with `Go` back in 2019, but for some work reason, I stopped working with it. Lately, I did a freshen up, and I see that a lot of `funcs` are repetitive in my code base. Thus, I decided to move them to a `helpers` package for reusability.

### Installation

```sh
go get https://github.com/mbougarne/gohelpers
```

### Usage

It's straightforward and easy to use, import the `gohelpers` package, and use its funcs. To work with `dotenv` you'll need to call the `LoadDotEnvToOsEnv` func on the `main` func, the default use case for this assumes that you have `.env` file in the root directory, if not you can pass the file name as an arg to that func. For more advanced and highly trustable `dotenv` in `Go` It's better to use [godotenv](https://github.com/joho/godotenv).

### Contributing

Contributions are more than welcome. As in [The Motif](#the-motif), I'm new in the `Go`, if you see that you can help, by improving tests, code, implement new functionalities, the readme file. You're welcome.
