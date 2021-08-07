defmodule Pbkdf2KeyDerivationTest do
  use ExUnit.Case
  import Pbkdf2KeyDerivation

  # Test data compiled by Anti-weakpasswords
  # https://stackoverflow.com/a/48352969
  # https://github.com/Anti-weakpasswords/PBKDF2-Test-Vectors

  @tag timeout: :infinity
  test "sha from file" do
    test_pbkdf2_from_file("pbkdf2_sha_tests.txt", :sha)
  end

  @tag timeout: :infinity
  test "sha256 from file" do
    test_pbkdf2_from_file("pbkdf2_sha256_tests.txt", :sha256)
  end

  @tag timeout: :infinity
  test "sha512 from file" do
    test_pbkdf2_from_file("pbkdf2_sha512_tests.txt", :sha512)
  end

  defp test_pbkdf2_from_file(file, algo) do
    Path.join("test", file)
    |> File.stream!()
    |> Enum.each(fn line ->
      line
      |> String.split(",")
      |> case do
        [pw, salt, it, key_bytes, expected] ->
          it =
            try do
              String.to_integer(it)
            rescue
              _ -> raise "invalid iteration count #{it} in #{file}"
            end

          key_bytes =
            try do
              String.to_integer(key_bytes)
            rescue
              _ -> raise "invalid key_bytes count #{key_bytes} in #{file}"
            end

          IO.inspect([pw, salt, algo, it, key_bytes])
          assert pbkdf2!(pw, salt, algo, it, key_bytes) |> Base.encode16() ==
                   String.trim(expected)

        _ ->
          raise "Invalid line\n#{line}\nin #{file}"
      end
    end)
  end
end
