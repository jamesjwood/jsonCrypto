/*global module */
/*global LOG_INFO */

module.exports = function(config) {
	'use strict';
    config.set({
		browsers : ['Safari'],
		frameworks: ['mocha'],
		basePath : 'stage/',
		files: [
			'../lib/forge.min.js',
			'test.js'
		],
        port: 9878
	});
};

