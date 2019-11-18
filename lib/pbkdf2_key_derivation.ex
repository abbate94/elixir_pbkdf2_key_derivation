defmodule Pbkdf2KeyDerivation do
  @doc ~S"""
  Derives a key of length `key_bytes` for `pass`,
  using `algo` and `salt` for `count` iterations.

  `algo` can be one of `:sha | :sha256 | :sha512`

  ## Example
  ```
  iex> Pbkdf2KeyDerivation.pbkdf2(:sha512, "password", "salt", 1000, 64) |> Base.encode16
  "AFE6C5530785B6CC6B1C6453384731BD5EE432EE549FD42FB6695779AD8A1C5BF59DE69C48F774EFC4007D5298F9033C0241D5AB69305E7B64ECEEB8D834CFEC"
  ```
  """
  def pbkdf2(algo, pass, salt, count, key_bytes) do
    case hash_size(algo) do
      {:ok, hash_bytes} ->
        if key_bytes <= (:math.pow(2, 32) - 1) * hash_bytes do
          pbkdf2(algo, pass, salt, count, key_bytes, hash_bytes)
        else
          {:error, "key_bytes is too long"}
        end

      err ->
        err
    end
  end

  defp pbkdf2(algo, pass, salt, count, key_bytes, hash_bytes) do
    block_count =
      (key_bytes / hash_bytes)
      |> :math.ceil()
      |> trunc

    remaining_bytes = key_bytes - (block_count - 1) * hash_bytes

    ts =
      1..(block_count + 1)
      |> Enum.map(fn e -> f(algo, pass, salt, count, e) end)

    t_last =
      List.last(ts)
      |> binary_part(0, remaining_bytes)

    ts
    |> Enum.drop(-1)
    |> Kernel.++([t_last])
    |> Enum.join()
    |> binary_part(0, key_bytes)
  end

  defp f(algo, p, s, c, i) do
    u1 = :crypto.mac(:hmac, algo, p, s <> <<i::32>>)

    Stream.iterate(u1, &:crypto.mac(:hmac, algo, p, &1))
    |> Enum.take(c)
    |> Enum.reduce(fn e, acc -> :crypto.exor(e, acc) end)
  end

  defp hash_size(:sha), do: {:ok, 20}
  defp hash_size(:sha256), do: {:ok, 32}
  defp hash_size(:sha512), do: {:ok, 64}
  defp hash_size(_), do: {:error, "Unsupported algorithm"}
end
