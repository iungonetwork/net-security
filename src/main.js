const ip_route = require('iproute').route
const collector = require('./collectors/udp_multisource').create()
const reporter = require('./reporters/amqp').create()
const log = require('./log')('main')
const net = require('net')
const repl = require('repl')

// list enabled sensors here
const enabledSensors = [
	'spam', 
	'portscan', 
	'winscan',
]

// setup sensors
const sensors = {}

enabledSensors.forEach(sensorName => {
	const sensor = require(`./sensors/${sensorName}`)()
	sensor.attachCollector(collector)
	reporter.attachSensor(sensor)
	sensors[sensorName] = sensor
	log.info('added sensor "%s"', sensor)
})

// connect to reporting
reporter.connect(
	process.env.AMQP_REPORTING_URI || 'amqp://user:pass@rabbitmq:5672', 
	process.env.AMQP_REPORTING_QUEUE || 'security-threat'
)

// listen for incoming flows
collector.listen(process.env.COLLECTOR_LISTEN_PORT || 3000)

net.createServer((socket) => {
	const replServer = repl.start({
		prompt: '> ',
		input: socket,
		output: socket
	})
	.on('exit', () => {
		socket.end();
	});

	replServer.context.reporter = reporter
	replServer.context.sensors = sensors
	replServer.context.collector = collector

}).listen(process.env.REPL_PORT || 5000);
