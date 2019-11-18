defmodule Pbkdf2KeyDerivation.MixProject do
  use Mix.Project

  def project do
    [
      app: :pbkdf2_key_derivation,
      version: "1.0.0",
      elixir: "~> 1.9",
      build_embedded: Mix.env() == :prod,
      start_permanent: Mix.env() == :prod,
      description: description(),
      package: package(),
      deps: deps(),
      source_url: "https://github.com/abbate94/elixir_pbkdf2_key_derivation"
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp description() do
    "Elixir module for deriving keys using the PBKDF2 key derivation algorithm, with sha1, sha256 or sha512 as hmac."
  end

  defp package() do
    [
      files: ~w(lib .formatter.exs mix.exs README.md LICENSE.md),
      licenses: ["Unlicense"],
      links: %{"GitHub" => "https://github.com/abbate94/elixir_pbkdf2_key_derivation"}
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:ex_doc, "~> 0.14", only: :dev, runtime: false}
    ]
  end
end
