var Hapi = null; // Initialized during plugin registration
var fs = require('fs');
var path = require('path');
var config = require('config');

exports.name    = 'report';
exports.version = '1.0.0';

var internals = {};

internals.defaults = {
    title: 'Report Plugin'
};

exports.register = function (plugin, options, next) {
    internals.setHapi(plugin.hapi);
    var Utils = plugin.hapi.utils;
    var settings = Utils.applyToDefaults(internals.defaults, options);

    require('./routes.js')(plugin);
    plugin.log(['info', 'report'], 'report plugin registered');
    next();
};

internals.setHapi = function (module) {
    Hapi = Hapi || module;
};