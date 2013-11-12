var getWatchers = require('getWatchers');
var pkg = require('./package.json');

module.exports = function(grunt) {
  "use strict";
  // Project configuration.
  grunt.initConfig({
   watch: {
      js: {
        options: {
          debounceDelay: 5000,
          interrupt: true
        },
        files: getWatchers(pkg),
        tasks: ['default']
      }
    },
    jshint: {
      options: {
        browser: true,
        node: true
      },
      all: ['index.js', 'test.js']
    },
    simplemocha: {
      options: {
        ui: 'bdd',
        reporter: 'tap'
      },
      all: { src: ['test.js'] }
    },
    browserify: {
      tests:{
        dest: './stage/test.js',
        src: ['./node_modules/node-forge/js/rsa.js','./test.js'],
        options: {
            ignore: ['node-forge']
        }
      }
    },
    shell: {
      makeStage: {
        command: 'rm -rf stage; mkdir stage',
        options:{
          stdout: true,
          stderr: true,
          failOnError: true
        }
      },
      makeLib: {
        command: 'rm -rf lib; mkdir lib',
        options:{
          stdout: true,
          stderr: true,
          failOnError: true
        }
      },
      browserify:{
        command: 'node ./node_modules/browserify/bin/cmd.js  --debug -o ./stage/test.js -i domain -e ./test.js;',
        options:{
          stdout: true,
          stderr: true,
          failOnError: true
        }
      }
    },
    karma: {
      local: {
        configFile: 'karma.conf.js',
        singleRun: true,
        browsers: ['Safari'] //, 'Firefox', 'Safari', 'Opera'
      }
    },
    bump: {
        options: {},
        files: [ 'package.json']
    }
  });


grunt.registerTask('bundleForge', function(){
  /* Bundle and minify Forge RSA and dependencies. */
  var fs = require('fs');
  var path = require('path');
  //var UglifyJS = require('uglify-js');

  // list dependencies in order
  var files = [
  'pkcs7asn1.js',
  'mgf.js',
  'mgf1.js',
  'md.js',
  'tls.js',
  'task.js',
  'rc2.js',
  'pem.js',
  'pbe.js',
  'x509.js',
  'pss.js',
  'pkcs7.js',
  'pkcs12.js',
  'pbkdf2.js',
  'log.js',
  'aesCipherSuites.js',
  'des.js',
  'debug.js',
  'util.js',
  'md5.js',
  'sha1.js',
  'sha256.js',
  'prng.js',
  'random.js',
  'hmac.js',
  'jsbn.js',
  'oids.js',
  'asn1.js',
  'rsa.js',
  'pki.js',
  'aes.js',
  'pkcs1.js'
  ];

  


  files = files.map(function(file) {
    return path.join(__dirname, 'node_modules/node-forge/js', file);
  });

  // bundle and minify JS
  console.log('Creating RSA bundle...');

  var bundle = path.join(__dirname, 'lib', 'forge.js');

  // FIXME: minification is turned off at the moment because it seems to have
  // negatively affected performance
  //fs.writeFileSync(bundle, UglifyJS.minify(files).code);
  var concat = '';
  files.forEach(function(file) {
    concat += fs.readFileSync(file);
  });
  fs.writeFileSync(bundle, concat);

  console.log('RSA bundle written to: ' + bundle);
});


require('matchdep').filterDev('grunt-*').forEach(grunt.loadNpmTasks);

grunt.registerTask('installold', 'shell:makeLib', 'bundleForge');
grunt.registerTask('install', []);
grunt.registerTask('test', ['simplemocha','shell:makeStage','shell:browserify', 'karma']);
grunt.registerTask('default', ['jshint', 'bump']);
};