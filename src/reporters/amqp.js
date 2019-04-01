/*
	AMQP threat reporter

	Pushes reported threats to AMQP queue.
*/

const amqp = require('amqp-connection-manager')
const log = require('../log')('reporters:amqp')

class AmqpReporter {

	connect(uri, queue) {
		this.uri = uri
		this.queue = queue
		this.connection = amqp.connect([this.uri])
		this.channel = this.connection.createChannel({
		 	json: true,
		  	setup: function(channel) {
		        const q = channel.assertQueue(queue, {durable: true})
		  		log.debug('connected to rabbitmq at %s, using queue "%s"', uri, queue)
		        return q
		    }
		})
	}

	reportThreat(threat) {
		const msg = {
			observer: threat.observer,
			offender: threat.offender,
			type: threat.type,
			details: threat.details
		}

		log.debug('reporting threat %o to "%s" at %s', msg, this.queue, this.uri)
		this.channel.sendToQueue(this.queue, msg, {contentType: 'application/json'}).then(_ => {
			log.debug('threat reported %o to "%s"', msg, this.queue)
		}).catch(err => {
			log.debug('could not report threat %o: %s', msg, err)
		})
	}

	attachSensor(sensor) {
		sensor.on('threat', threat => this.reportThreat(threat))
	}
}

module.exports = {
	create: function() {
		return new AmqpReporter()
	}
}