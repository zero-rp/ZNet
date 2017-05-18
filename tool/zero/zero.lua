local skynet = require "skynet"
require "skynet.manager"	-- import skynet.register

local max_client = 99999

skynet.start(function()
	skynet.error("[LOG]",os.date("%m-%d-%Y %X", skynet.starttime()),"Server start")
	--启动调试器
	skynet.newservice("debug_console",8000)
	--启动watchdog
	skynet.launch("watchdog", "0.0.0.0", 8888, max_client)
	--启动js脚本
	skynet.launch("snjs", "test")
	--local watchdog = skynet.newservice("watchdog")
	--skynet.call(watchdog, "lua", "start", {
	--	ip = "0.0.0.0",
	--	port = 8888,
	--	maxclient = max_client,
	--})
	--退出服务
	skynet.exit()
end)