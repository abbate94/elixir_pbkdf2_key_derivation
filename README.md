# Elixir Pbkdf2KeyDerivation

Elixir module for deriving keys using the PBKDF2 key derivation algorithm, with sha1, sha256 or sha512 as hmac.

## Installation

The package can be installed by adding `pbkdf2_key_derivation` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:pbkdf2_key_derivation, "~> 1.0.2"}
  ]
end
```

## Usage
Docs: [https://hexdocs.pm/pbkdf2_key_derivation](https://hexdocs.pm/pbkdf2_key_derivation).

To derive a key, use:
```elixir
Pbkdf2KeyDerivation.pbkdf2!(algo, password, salt, count, key_bytes) 
```

where:
- `algo` is one of `:sha | :sha256 | :sha512`<br>
- `password` is a `binary` containing the password
- `salt` is a `binary` containing the salt
- `count`is the number of iterations (positive int)
- `key_bytes` is the desired length of the direved key in bytes (positive int)

Raises an `ArgumentError` on error.
To get a tuple `{:ok, hash}|{:error, err_msg}` instead of raising use:

```elixir
Pbkdf2KeyDerivation.pbkdf2(algo, password, salt, count, key_bytes) 
```

without the `!`

## Examples
Derive a 32 byte key using 1000 iterations of sha256 on the password `"password"` and salt `"salt"`

```elixir
iex> Pbkdf2KeyDerivation.pbkdf2!(:sha256, "password", "salt", 1000, 32)  
<<99, 44, 40, 18, 228, 109, 70, 4, 16, 43, 167, 97, 142, 157, 109, 125, 47, 129, 40, 246, 38, 107, 74, 3, 38, 77, 42, 4, 96, 183, 220, 179>>
```

Derive a 64 byte key using 1000 iterations of sha512 on the password `"password"` and a random 16 byte salt.
```elixir
iex> Pbkdf2KeyDerivation.pbkdf2!(:sha512, "password", :crypto.strong_rand_bytes(16), 1000, 64)
<<245, 233, 241, 60, 152, 100, 127, 147, 62, 163, 120, 246, 192, 172, 170, 81, 92, 203, 204, 169, 50, 37, 88, 128, 7, 146, 10, 154, 207, 77, 42, 81, 155, 16, 213, 100, 86, 216, 87, 240, 207, 6, 163, 37, 137, 165, 213, 57, 2, 147, ...>>
```
Derive a 20 byte key using 1000 iterations of sha1 on the password `"password"` and salt `"salt"` and encode it using [Base.encode16/2](https://hexdocs.pm/elixir/Base.html#encode16/2)
```elixir
iex> Pbkdf2KeyDerivation.pbkdf2!(:sha, "password", "salt", 1000, 20) |> Base.encode16
"6E88BE8BAD7EAE9D9E10AA061224034FED48D03F"
```

## Test data
Compiled by Anti-weakpasswords<br>
https://stackoverflow.com/a/48352969<br>
https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors<br>

## License
<p xmlns:dct="http://purl.org/dc/terms/">

<a rel="license"
   href="http://creativecommons.org/publicdomain/zero/1.0/">
  <img src="http://i.creativecommons.org/p/zero/1.0/88x31.png" style="border-style: none;" alt="CC0" />
</a>
<br />
To the extent possible under law,
<a rel="dct:publisher"
   href="https://github.com/abbate94/elixir_pbkdf2_key_derivation">https://github.com/abbate94/elixir_pbkdf2_key_derivation</a>
has waived all copyright and related or neighboring rights to
this work.
</p>
