const debug = require('debug')('iungo:sec')

module.exports = function(namespace) {
	const error = debug.extend(namespace).extend('error')
	const info  = debug.extend(namespace).extend('info')
	const _debug  = debug.extend(namespace).extend('debug')
	info.log = console.log.bind(console) // log info to std out
	_debug.log = console.log.bind(console) // log debug to std out
	return {
		info: info,
		error: error,
		debug: _debug
	}
}