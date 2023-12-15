# PoC basic async Electum client (Rust crate)

This implements a simple `async` Electrum client with support of notifications etc.

This is a piece of code taken out from a different project. While it works in the project, I did not have time to test it or develop it further. It's provided as a starting point for anyone who would like to implement it properly. It was only tested with electrs, may have unknown bugs when ran with other servers. It has known missing functionality that I didn't need and may have other various issues such as too bloated dep tree, inefficient parsing...

Please don't report issues, just fork it and write your own. But feel free to let me know when you have something usable, so I can point people at yours and probably use it too. In that case I will contribute to your fork if I have time and need to improve things.

The MSRV is 1.48.0 and `Cargo.lock` is provided for those who need the correct version numbers of the dependencies.

## License

WTFPL

But I'd be happy if you decide to give me credit. :)
