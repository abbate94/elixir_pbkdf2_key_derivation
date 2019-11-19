defmodule Pbkdf2KeyDerivation do
  @doc ~S"""
  Derives a key of length `key_bytes` for `pass`,
  using `algo` and `salt` for `count` iterations.

  To raise on error use `Pbkdf2KeyDerivation.pbkdf2!/5`

  ## Example
  ```
  iex> Pbkdf2KeyDerivation.pbkdf2(:sha512, "password", "salt", 1000, 64)
  {:ok,
  <<175, 230, 197, 83, 7, 133, 182, 204, 107, 28, 100, 83, 56, 71, 49, 189, 94,
  228, 50, 238, 84, 159, 212, 47, 182, 105, 87, 121, 173, 138, 28, 91, 245,
  157, 230, 156, 72, 247, 116, 239, 196, 0, 125, 82, 152, 249, 3, 60, _rest>>}
  ```
  """
  @spec pbkdf2(:sha | :sha256 | :sha512, binary, binary, pos_integer, pos_integer) ::
          {:error, String.t()} | {:ok, binary}
  def pbkdf2(_algo, _pass, _salt, count, _key_bytes) when count <= 0 do
    {:error, "count must be positive"}
  end

  def pbkdf2(_algo, _pass, _salt, _count, key_bytes) when key_bytes <= 0 do
    {:error, "key_bytes must be positive"}
  end

  def pbkdf2(algo, pass, salt, count, key_bytes) do
    case hash_size(algo) do
      {:ok, hash_bytes} ->
        if key_bytes <= (:math.pow(2, 32) - 1) * hash_bytes do
          {:ok, pbkdf2(algo, pass, salt, count, key_bytes, hash_bytes)}
        else
          {:error, "key_bytes is too long"}
        end

      err ->
        err
    end
  end

  @doc ~S"""
  Derives a key of length `key_bytes` for `pass`,
  using `algo` and `salt` for `count` iterations.

  To return a tuple instead of raising use `Pbkdf2KeyDerivation.pbkdf2/5`

  ## Example
  ```
  iex> Pbkdf2KeyDerivation.pbkdf2(:sha512, "password", "salt", 1000, 64)
  <<175, 230, 197, 83, 7, 133, 182, 204, 107, 28, 100, 83, 56, 71, 49, 189, 94,
  228, 50, 238, 84, 159, 212, 47, 182, 105, 87, 121, 173, 138, 28, 91, 245,
  157, 230, 156, 72, 247, 116, 239, 196, 0, 125, 82, 152, 249, 3, 60, _rest>>
  ```
  """
  @spec pbkdf2!(:sha | :sha256 | :sha512, binary, binary, pos_integer, pos_integer) :: binary
  def pbkdf2!(_algo, _pass, _salt, count, _key_bytes) when count <= 0 do
    raise ArgumentError, message: "count must be positive"
  end

  def pbkdf2!(_algo, _pass, _salt, _count, key_bytes) when key_bytes <= 0 do
    raise ArgumentError, message: "key_bytes must be positive"
  end

  def pbkdf2!(algo, pass, salt, count, key_bytes) do
    case hash_size(algo) do
      {:ok, hash_bytes} ->
        if key_bytes <= (:math.pow(2, 32) - 1) * hash_bytes do
          pbkdf2(algo, pass, salt, count, key_bytes, hash_bytes)
        else
          raise ArgumentError, message: "key_bytes is too long"
        end

      {:error, err} ->
        raise ArgumentError, message: err
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
  defp hash_size(algo), do: {:error, "Unsupported algorithm #{algo}"}
end
