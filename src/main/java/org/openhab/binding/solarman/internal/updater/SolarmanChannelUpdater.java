package org.openhab.binding.solarman.internal.updater;

import org.apache.commons.lang3.StringUtils;
import org.eclipse.jdt.annotation.Nullable;
import org.openhab.binding.solarman.internal.defmodel.ParameterItem;
import org.openhab.binding.solarman.internal.defmodel.Request;
import org.openhab.binding.solarman.internal.defmodel.Validation;
import org.openhab.binding.solarman.internal.modbus.ISolarmanProtocol;
import org.openhab.binding.solarman.internal.modbus.SolarmanLoggerConnection;
import org.openhab.binding.solarman.internal.modbus.SolarmanLoggerConnector;
import org.openhab.binding.solarman.internal.state.LoggerState;
import org.openhab.binding.solarman.internal.typeprovider.ChannelUtils;
import org.openhab.binding.solarman.internal.util.StreamUtils;
import org.openhab.core.library.types.DateTimeType;
import org.openhab.core.library.types.DecimalType;
import org.openhab.core.library.types.QuantityType;
import org.openhab.core.library.types.StringType;
import org.openhab.core.thing.ChannelUID;
import org.openhab.core.types.State;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.measure.Unit;
import javax.measure.format.MeasurementParseException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.openhab.binding.solarman.internal.util.StreamUtils.reverse;

public class SolarmanChannelUpdater {
    private final Logger LOGGER = LoggerFactory.getLogger(SolarmanChannelUpdater.class);
    private final StateUpdater stateUpdater;

    public SolarmanChannelUpdater(StateUpdater stateUpdater) {
        this.stateUpdater = stateUpdater;
    }

    public boolean fetchDataFromLogger(List<Request> requests,
                                       SolarmanLoggerConnector solarmanLoggerConnector,
                                       ISolarmanProtocol solarmanProtocol,
                                       Map<ParameterItem, ChannelUID> paramToChannelMapping,
                                       LoggerState loggerState) {

        try (SolarmanLoggerConnection solarmanLoggerConnection = solarmanLoggerConnector.createConnection()) {
            LOGGER.debug("Fetching data from logger");

            Map<Integer, byte[]> readRegistersMap = requests.stream()
                    .map(request -> solarmanProtocol.readRegisters(solarmanLoggerConnection,
                            (byte) request.getMbFunctioncode().intValue(),
                            request.getStart(),
                            request.getEnd(),
                            !loggerState.isOffline())
                    )
                    .reduce(new HashMap<>(), this::mergeMaps);

            if (!readRegistersMap.isEmpty())
                updateChannelsForReadRegisters(paramToChannelMapping, readRegistersMap);

            return !readRegistersMap.isEmpty();
        } catch (Exception e) {
            LOGGER.error("Error invoking handler", e);
            return false;
        }
    }

    private void updateChannelsForReadRegisters(Map<ParameterItem, ChannelUID> paramToChannelMapping,
                                                Map<Integer, byte[]> readRegistersMap) {
        paramToChannelMapping.forEach((parameterItem, channelUID) -> {
            List<Integer> registers = parameterItem.getRegisters();
            if (readRegistersMap.keySet().containsAll(registers)) {
                switch (parameterItem.getRule()) {
                    case 1, 3 -> updateChannelWithNumericValue(parameterItem, channelUID, registers,
                            readRegistersMap, ValueType.UNSIGNED);
                    case 2, 4 -> updateChannelWithNumericValue(parameterItem, channelUID, registers,
                            readRegistersMap, ValueType.SIGNED);
                    case 5 -> updateChannelWithStringValue(channelUID, registers, readRegistersMap);
                    case 6 -> updateChannelWithRawValue(parameterItem, channelUID, registers, readRegistersMap);
                    case 7 -> updateChannelWithVersion(channelUID, registers, readRegistersMap);
                    case 8 -> updateChannelWithDateTime(channelUID, registers, readRegistersMap);
                    case 9 -> updateChannelWithTime(channelUID, registers, readRegistersMap);
                }
            } else {
                LOGGER.error("Unable to update channel {} because its registers were not read", channelUID.getId());
            }
        });
    }

    private void updateChannelWithTime(ChannelUID channelUID, List<Integer> registers, Map<Integer, byte[]> readRegistersMap) {
        String stringValue = registers.stream()
                .map(readRegistersMap::get)
                .map(v -> ByteBuffer.wrap(v).getShort())
                .map(rawVal -> String.format("%02d", rawVal / 100) + ":" +
                        String.format("%02d", rawVal % 100))
                .collect(Collectors.joining());

        stateUpdater.updateState(channelUID, new StringType(stringValue));
    }

    private void updateChannelWithDateTime(ChannelUID channelUID, List<Integer> registers, Map<Integer, byte[]> readRegistersMap) {
        String stringValue = StreamUtils.zip(
                        IntStream.range(0, registers.size()).boxed(),
                        registers.stream().map(readRegistersMap::get).map(v -> ByteBuffer.wrap(v).getShort()),
                        StreamUtils.Tuple::new)
                .map(t -> {
                    int index = t.a();
                    short rawVal = t.b();

                    return switch (index) {
                        case 0 -> (rawVal >> 8) + "/" + (rawVal & 0xFF) + "/";
                        case 1 -> (rawVal >> 8) + " " + (rawVal & 0xFF) + ":";
                        case 2 -> (rawVal >> 8) + ":" + (rawVal & 0xFF);
                        default -> (rawVal >> 8) + "" + (rawVal & 0xFF);
                    };
                })
                .collect(Collectors.joining());

        try {
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yy/M/d H:m:s");
            LocalDateTime dateTime = LocalDateTime.parse(stringValue, formatter);

            stateUpdater.updateState(channelUID, new DateTimeType(dateTime.atZone(ZoneId.systemDefault())));
        } catch (DateTimeParseException e) {
            LOGGER.error("Unable to parse string date {} to a DateTime object", stringValue);
        }
    }

    private void updateChannelWithVersion(ChannelUID channelUID, List<Integer> registers, Map<Integer, byte[]> readRegistersMap) {
        String stringValue = registers.stream()
                .map(readRegistersMap::get)
                .map(v -> ByteBuffer.wrap(v).getShort())
                .map(rawVal -> (rawVal >> 12) + "." +
                        ((rawVal >> 8) & 0x0F) + "." +
                        ((rawVal >> 4) & 0x0F) + "." +
                        (rawVal & 0x0F))
                .collect(Collectors.joining());

        stateUpdater.updateState(channelUID, new StringType(stringValue));
    }

    private void updateChannelWithStringValue(ChannelUID channelUID, List<Integer> registers, Map<Integer, byte[]> readRegistersMap) {
        String stringValue = registers.stream().map(readRegistersMap::get).reduce(new StringBuilder(), (acc, val) -> {
            short shortValue = ByteBuffer.wrap(val).order(ByteOrder.BIG_ENDIAN).getShort();
            return acc.append((char) (shortValue >> 8)).append((char) (shortValue & 0xFF));
        }, StringBuilder::append).toString();

        stateUpdater.updateState(channelUID, new StringType(stringValue));
    }

    private void updateChannelWithNumericValue(ParameterItem parameterItem, ChannelUID channelUID,
                                               List<Integer> registers, Map<Integer, byte[]> readRegistersMap, ValueType valueType) {
        BigInteger value = extractNumericValue(registers, readRegistersMap, valueType);
        BigDecimal convertedValue = convertNumericValue(value, parameterItem.getOffset(), parameterItem.getScale());
        if (validateNumericValue(convertedValue, parameterItem.getValidation())) {
            State state;
            if (StringUtils.isNotEmpty(parameterItem.getUom())) {
                try {
                    Unit<?> unitFromDefinition = ChannelUtils.getUnitFromDefinition(parameterItem.getUom());
                    if (unitFromDefinition != null)
                        state = new QuantityType<>(convertedValue, unitFromDefinition);
                    else {
                        LOGGER.debug("Unable to parse unit: {}", parameterItem.getUom());
                        state = new DecimalType(convertedValue);
                    }
                } catch (MeasurementParseException e) {
                    state = new DecimalType(convertedValue);
                }

            } else {
                state = new DecimalType(convertedValue);
            }
            stateUpdater.updateState(channelUID, state);
        }
    }

    private void updateChannelWithRawValue(ParameterItem parameterItem, ChannelUID channelUID, List<Integer> registers,
                                           Map<Integer, byte[]> readRegistersMap) {
        String hexString = String.format("[%s]",
                reverse(registers).stream()
                        .map(readRegistersMap::get)
                        .map(val -> String.format("0x%02X", ByteBuffer.wrap(val).order(ByteOrder.BIG_ENDIAN).getShort()))
                        .collect(Collectors.joining(",")));

        stateUpdater.updateState(channelUID, new StringType(hexString));
    }


    private boolean validateNumericValue(BigDecimal convertedValue, Validation validation) {
        return true;
    }

    private BigDecimal convertNumericValue(BigInteger value, @Nullable BigDecimal offset, @Nullable BigDecimal scale) {
        return new BigDecimal(value).subtract(offset != null ? offset : BigDecimal.ZERO)
                .multiply(scale != null ? scale : BigDecimal.ONE);
    }

    private BigInteger extractNumericValue(List<Integer> registers, Map<Integer, byte[]> readRegistersMap, ValueType valueType) {
        return reverse(registers).stream().map(readRegistersMap::get).reduce(BigInteger.ZERO,
                (acc, val) -> acc.shiftLeft(Short.SIZE).add(BigInteger.valueOf(ByteBuffer.wrap(val).getShort() & (valueType == ValueType.UNSIGNED ? 0xFFFF : 0xFFFFFFFF))),
                BigInteger::add);
    }

    private <K, V> Map<K, V> mergeMaps(Map<K, V> map1,
                                       Map<K, V> map2) {
        return Stream.concat(map1.entrySet().stream(), map2.entrySet().stream())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (v1, v2) -> v1));
    }

    private enum ValueType {
        UNSIGNED, SIGNED
    }

    @FunctionalInterface
    public interface StateUpdater {
        void updateState(ChannelUID channelUID, State state);
    }
}
