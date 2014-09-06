var Hapi        = null; // Initialized during plugin registration
var advisories  = require('nodesecurity-advisories');
var validate    = require('./validate');
var semver      = require('semver');

exports.name    = 'advisories';
exports.version = '1.0.0';

var internals = {};

internals.defaults = {
  title: 'Advisories'
};

// NOTE:
// There is a issue with Walker and therefore this is not working yet
// Walker doesn't work well with paths 2 or more level deep
// 


exports.register = function (plugin, options, next) {
  plugin.log(['info', 'advisories'], 'advisories plugin registered');

  internals.setHapi(plugin.hapi);
  var Utils = plugin.hapi.utils;
  var settings = Utils.applyToDefaults(internals.defaults, options);
  var module_index;
  advisories(function (err, mi) {
    if (err) {
      plugin.log(['err', 'advisories'], err);
    }
    module_index = mi;
  });


  // npm shrinkwrap search
  plugin.route({
    method: 'POST',
    path: '/validate/shrinkwrap',
    config: {
      payload: {
        allow: 'application/json'
      }
    },
    handler: function (request, reply) {
      reply(validate(request.payload, module_index));
    }
  });

  plugin.route({
    method: 'GET',
    path: '/validate/{module}/{versions}',
    handler: function (request, reply) {
      var data = module_index[request.params.module] || {};
      var result = [];
      var versions = request.params.versions.split(',');

      Object.keys(data).forEach(function (key) {
        var advisory = data[key];
        var added = false;

        versions.forEach(function (v) {
          if (semver.valid(v) && semver.satisfies(v, advisory.vulnerable_versions) && !added) {
            result.push(advisory);
            added = true;
          }
        });
      });
      reply(result);
    }
  });
  next();
};


internals.setHapi = function (module) {
  Hapi = Hapi || module;
};
