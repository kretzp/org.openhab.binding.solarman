package org.openhab.binding.solarman.internal.modbus;

import java.util.Map;

public interface ISolarmanProtocol {

	Map<Integer, byte[]> readRegisters(SolarmanLoggerConnection solarmanLoggerConnection, byte mbFunctionCode,
			int firstReg, int lastReg, Boolean allowLogging);

}