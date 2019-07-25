defmodule HanAms.Parser do
  def parse(bytes) do
    <<0x7E, header::size(18), rest>> = bytes
    IO.inspect(rest)
  end
end
