package org.openhab.binding.solarman.internal.modbus;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

import org.openhab.binding.solarman.internal.SolarmanLoggerConfiguration;
import org.openhab.binding.solarman.internal.SolarmanLoggerHandler;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author Catalin Sanda - Initial contribution
 */
public class SolarmanRAWProtocol implements ISolarmanProtocol {
    private final static Logger LOGGER = LoggerFactory.getLogger(SolarmanLoggerHandler.class);
    private final SolarmanLoggerConfiguration solarmanLoggerConfiguration;

    public SolarmanRAWProtocol(SolarmanLoggerConfiguration solarmanLoggerConfiguration) {
        this.solarmanLoggerConfiguration = solarmanLoggerConfiguration;
    }

    public Map<Integer, byte[]> readRegisters(SolarmanLoggerConnection solarmanLoggerConnection, byte mbFunctionCode, int firstReg, int lastReg, Boolean allowLogging) {
    	byte[] solarmanRawFrame = buildSolarmanRawFrame(mbFunctionCode, firstReg, lastReg);
        byte[] respFrame = solarmanLoggerConnection.sendRequest(solarmanRawFrame, allowLogging);
        LOGGER.debug("respFrame: " + bytesToHex(respFrame));
        if (respFrame.length > 0) {
            byte[] modbusRespFrame = extractModbusResponseFrame(respFrame, solarmanRawFrame, allowLogging);
            LOGGER.debug("modbusRespFrame: " + bytesToHex(modbusRespFrame));
            return parseModbusReadHoldingRegistersResponse(modbusRespFrame, firstReg, lastReg, allowLogging);
        } else {
            return Collections.emptyMap();
        }
    }
    
    /**
     * Builds a SolarMAN Raw frame to request data from firstReg to lastReg.
     * Frame format is based on
     * <a href="https://github.com/StephanJoubert/home_assistant_solarman/issues/247">Solarman RAW Protocol</a>
     *     Request send: 
     * Header       03e8: Transaction identifier
     * Header       0000: Protocol identifier
     * Header       0006: Message length (w/o CRC)
     * Payload         01: Slave ID
     * Payload         03: Read function
     * Payload      0003: 1st register address
     * Payload      006e: Nb of registers to read 
     * Trailer      3426: CRC-16 ModBus
     * @param mbFunctionCode
     * @param firstReg       - the start register
     * @param lastReg        - the end register
     * @return byte array containing the Solarman Raw frame
     */
    protected byte[] buildSolarmanRawFrame(byte mbFunctionCode, int firstReg, int lastReg) {
        byte[] requestPayload = buildSolarmanRawFrameRequestPayload(mbFunctionCode, firstReg, lastReg);
        byte[] header = buildSolarmanRawFrameHeader(requestPayload.length);
        
        LOGGER.debug(String.format("mbFunctionCoe: %04x, firstReg: %04x, lastReg: %04x", mbFunctionCode, firstReg, lastReg));
        LOGGER.debug("requestPayload length: " + requestPayload.length);
        LOGGER.debug("header frame: " + bytesToHex(header));
        LOGGER.debug("requestPayload frame: " + bytesToHex(requestPayload));
        
        return ByteBuffer.allocate(header.length + requestPayload.length).put(header)
                .put(requestPayload).array();
    }
    
    /**
     * Builds a SolarMAN Raw frame Header
     * Frame format is based on
     * <a href="https://github.com/StephanJoubert/home_assistant_solarman/issues/247">Solarman RAW Protocol</a>
     *     Request send: 
     * Header       03e8: Transaction identifier
     * Header       0000: Protocol identifier
     * Header       0006: Message length (w/o CRC)
     * @param payloadSize
     * @return byte array containing the Solarman Raw frame header
     */
    private byte[] buildSolarmanRawFrameHeader(int payloadSize) {
        // (two byte) Denotes the start of the Raw frame. Always 0x03 0xE8.
        byte[] transactionId = new byte[]{(byte) 0x03, (byte) 0xE8};

        // (two bytes) – Always 0x00 0x00
        byte[] protocolId = new byte[]{(byte) 0x00, (byte) 0x00};
        
        // (two bytes) Payload length
        byte[] messageLength = ByteBuffer.allocate(Short.BYTES).order(ByteOrder.BIG_ENDIAN).putShort((short) payloadSize)
                .array();

        // Append all fields into the header
        return ByteBuffer
                .allocate(transactionId.length + protocolId.length + messageLength.length)
                .put(transactionId).put(protocolId).put(messageLength).array();
    }
    
    /**
     * Builds a SolarMAN Raw frame payload
     * Frame format is based on
     * <a href="https://github.com/StephanJoubert/home_assistant_solarman/issues/247">Solarman RAW Protocol</a>
     *     Request send: 
     * Payload         01: Slave ID
     * Payload         03: Read function
     * Payload      0003: 1st register address
     * Payload      006e: Nb of registers to read 
     * Trailer      3426: CRC-16 ModBus
     * @param mbFunctionCode
     * @param firstReg       - the start register
     * @param lastReg        - the end register
     * @return byte array containing the Solarman Raw frame payload
     */
    protected byte[] buildSolarmanRawFrameRequestPayload(byte mbFunctionCode, int firstReg, int lastReg) {
        int regCount = lastReg - firstReg + 1;
        byte[] req = ByteBuffer.allocate(6).put((byte) 0x01).put(mbFunctionCode).putShort((short) firstReg)
                .putShort((short) regCount).array();
        byte[] crc = ByteBuffer.allocate(Short.BYTES).order(ByteOrder.LITTLE_ENDIAN)
                .putShort((short) CRC16Modbus.calculate(req)).array();

        return ByteBuffer.allocate(req.length + crc.length).put(req).put(crc).array();
    }

    protected byte[] extractModbusResponseFrame(byte[] responseFrame, byte[] requestFrame, Boolean allowLogging) {
        if (responseFrame == null || responseFrame.length == 0) {
            if (allowLogging)
                LOGGER.error("No response frame");
            return null;
        } else if (responseFrame.length < 13) {
            if (allowLogging)
                LOGGER.error("Response frame is too short");
            return null;
        } else if (responseFrame[0] != (byte) 0x03) {
            if (allowLogging)
                LOGGER.error("Response frame has invalid starting byte");
            return null;
        }

        return Arrays.copyOfRange(responseFrame, 6, responseFrame.length);
    }

    protected Map<Integer, byte[]> parseModbusReadHoldingRegistersResponse(byte[] frame, int firstReg, int lastReg, Boolean allowLogging) {
        int regCount = lastReg - firstReg + 1;
        LOGGER.debug("regCount: " + regCount);
        Map<Integer, byte[]> registers = new HashMap<>();
        int expectedFrameDataLen = 2 + 1 + regCount * 2;
        LOGGER.debug("expectedFrameDataLen: " + expectedFrameDataLen);
        LOGGER.debug("frame.length: " + frame.length);
        if (frame == null || frame.length < expectedFrameDataLen) {
            if (allowLogging)
                LOGGER.error("Modbus frame is too short or empty");
            return registers;
        }

        for (int i = 0; i < regCount; i++) {
            int p1 = 3 + (i * 2);
            ByteBuffer order = ByteBuffer.wrap(frame, p1, 2).order(ByteOrder.BIG_ENDIAN);
            byte[] array = new byte[]{order.get(), order.get()};
            LOGGER.debug("register-" + (i + firstReg) + ": " + bytesToHex(array));
            registers.put(i + firstReg, array);
        }

        return registers;
    }

    protected void parseResponseErrorCode(byte[] responseFrame, byte[] requestFrame) {
        if (responseFrame[0] == (byte) 0xA5 && responseFrame[1] == (byte) 0x10 &&
                !Arrays.equals(Arrays.copyOfRange(responseFrame, 7, 11),
                        Arrays.copyOfRange(requestFrame, 7, 11))) {

            String requestInverterId = parseInverterId(requestFrame);
            String responseInverterId = parseInverterId(responseFrame);

            LOGGER.error(String.format("There was a missmatch between the request logger ID: %s and the response logger ID: %s . " +
                            "Make sure you are using the logger ID and not the inverter ID. If in doubt, try the one in the response",
                    requestInverterId,
                    responseInverterId));
            return;
        }

        if (responseFrame[1] != (byte) 0x10 || responseFrame[2] != (byte) 0x45) {
            LOGGER.error("Unexpected control code in error response frame");
            return;
        }

        int errorCode = responseFrame[25];
        switch (errorCode) {
            case 0x01 -> LOGGER.error("Error response frame: Illegal Function");
            case 0x02 -> LOGGER.error("Error response frame: Illegal Data Address");
            case 0x03 -> LOGGER.error("Error response frame: Illegal Data Value");
            case 0x04 -> LOGGER.error("Error response frame: Slave Device Failure");
            default -> LOGGER.error(String.format("Error response frame: Unknown error code %02x", errorCode));
        }
    }

    private static String parseInverterId(byte[] requestFrame) {
        byte[] inverterIdBytes = Arrays.copyOfRange(requestFrame, 7, 11);
        int inverterIdInt = ByteBuffer.wrap(inverterIdBytes).order(ByteOrder.LITTLE_ENDIAN).getInt();
        return String.valueOf(inverterIdInt & 0x00000000ffffffffL);
    }
    
    private static String bytesToHex(byte[] bytes) {
        return IntStream.range(0, bytes.length).mapToObj(i -> String.format("%02X", bytes[i]))
                .collect(Collectors.joining());
    }
}
