defmodule HanAms.Parser do
  alias ExCRC

  alias HanAms.Lists

  # 0x7E denotes start and end of message (HDLC Frame)
  def decode(<<rest::binary>>) do

    ## finn checksum
    # verifyChecksum(rest) # virker ikka akkurat nå

    ## fortsett å parse data
    parse(rest, %{meter_time: parseTimestamp(rest)})
  end


  defp parseTimestamp(<<
                      0x7E,
                      _::binary-size(16),
                      0x09,
                      some_length,
                      year::16,
                      month,
                      day,
                      _, # What is this? Nobody quite knows! ¯\_(ツ)_/¯
                      hour,
                      min,
                      sec,
                      _::binary>>) do
    NaiveDateTime.new(year, month, day, hour, min, sec, 0)
  end

  # Skip parts before data
  defp parse(<<
              0x7E,
              _::binary-size(16),
              0x09,
              len,
              _::binary-size(len),
              data::binary>>,
            acc) do
    parse(data, acc)
  end

  # message type
  defp parse(<<0x02, message_type, rest::binary>>, acc) do''
    parse(rest, put_in(acc[:list], message_type_to_list(message_type)))
  end

  # active power positive
  defp parse(<<0x06, act_pow_pos::size(32), rest::binary>>,
              %{list: %{act_pow_pos: nil}} = acc) do
    parse(rest, put_in(acc.list.act_pow_pos, act_pow_pos))
  end

  # obis list version
  defp parse(<<0x09, len, obis_list_version::binary-size(len), rest::binary>>,
              %{list: %Lists.ThreeFasesMessageType2{obis_list_version: nil}} = acc) do
    parse(rest, put_in(acc.list.obis_list_version, obis_list_version))
  end

  # gs1
  defp parse(<<0x09, len, gs1::binary-size(len), rest::binary>>,
               %{list: %Lists.ThreeFasesMessageType2{gs1: nil}} = acc) do
    parse(rest, put_in(acc.list.gs1, gs1))
  end

  # meter model
  defp parse(<<0x09, len, meter_model::binary-size(len), rest::binary>>,
               %{list: %Lists.ThreeFasesMessageType2{meter_model: nil}} = acc) do
    parse(rest, put_in(acc.list.meter_model, meter_model))
  end

  # active power negative
  defp parse(<< 0x06, act_pow_neg::size(32), rest::binary>>,
              %{list: %{act_pow_neg: nil}} = acc) do
    parse(rest, put_in(acc.list.act_pow_neg, act_pow_neg))
  end

  # reactive power positive
  defp parse(<< 0x06, react_pow_pos::size(32), rest::binary>>,
              %{list: %{react_pow_pos: nil}} = acc) do
    parse(rest, put_in(acc.list.react_pow_pos, react_pow_pos))
  end

  # reactive power negative
  defp parse(<< 0x06, react_pow_neg::size(32), rest::binary>>,
              %{list: %{react_pow_neg: nil}} = acc) do
    parse(rest, put_in(acc.list.react_pow_neg, react_pow_neg))
  end

  # Current phase L1
  defp parse(<< 0x06, curr_l1::size(32), rest::binary>>,
              %{list: %{curr_l1: nil}} = acc) do
    parse(rest, put_in(acc.list.curr_l1, curr_l1))
  end

  # Current phase L2
  defp parse(<< 0x06, curr_l2::size(32), rest::binary>>,
              %{list: %{curr_l2: nil}} = acc) do
    parse(rest, put_in(acc.list.curr_l2, curr_l2))
  end

  # Current phase L3
  defp parse(<< 0x06, curr_l3::size(32), rest::binary>>,
              %{list: %{curr_l3: nil}} = acc) do
    parse(rest, put_in(acc.list.curr_l3, curr_l3))
  end

  # Voltage L1
  defp parse(<< 0x06, volt_l1::size(32), rest::binary>>,
              %{list: %{volt_l1: nil}} = acc) do
    parse(rest, put_in(acc.list.volt_l1, volt_l1))
  end

  # Voltage L2
  defp parse(<< 0x06, volt_l2::size(32), rest::binary>>,
              %{list: %{volt_l2: nil}} = acc) do
    parse(rest, put_in(acc.list.volt_l2, volt_l2))
  end

  # Voltage L2
  defp parse(<< 0x06, volt_l3::size(32), rest::binary>>,
              %{list: %{volt_l3: nil}} = acc) do
    parse(rest, put_in(acc.list.volt_l3, volt_l3))
  end

  # datetime
  defp parse(<<0x09, len, meter_model::binary-size(len), rest::binary>>,
               %{list: %Lists.ThreeFasesMessageType2{meter_model: nil}} = acc) do
    parse(rest, put_in(acc.list.meter_model, meter_model))
  end


  defp message_type_to_list(message_type) do
    case message_type do
      1 -> %Lists.MessageType1{}
      13 -> %Lists.ThreeFasesMessageType2{}
      18 -> %Lists.ThreeFasesMessageType3{}
    end

  end

  # We done!
  defp parse(<< _::binary-size(2), 0x7E>>, acc) do
    acc
  end


  defp verifyChecksum(binary) do
    length  = byte_size(binary)

    bin = binary_part(binary, 0, length-3)

    <<package_checksum::16>> = binary_part(binary, length-3, 2)
    IO.inspect package_checksum

    # This returns 47435 when it should return 33085 :/
    calculated_checksum = ExCRC.crc16ccitt(bin)

    IO.inspect "testlol"
    IO.inspect package_checksum
    IO.inspect calculated_checksum
    unless package_checksum == calculated_checksum, do: exit("Checksum not matching")
  end
end
