/**
 * Poshmark iOS Network Traffic Sniffer - Fixed Version
 * Usage: frida -U -l poshmark_sniffer.js "Poshmark" > poshmark_traffic.txt
 */

console.log("🎯 POSHMARK NETWORK TRAFFIC ANALYSIS INITIATED");
console.log("============================================================");

// Global variables for data collection
var apiCalls = [];
var authTokens = [];
var discoveredEndpoints = [];

// Simplified anti-debugging bypass
function bypassAntiDebugging() {
    console.log("[🔓] Setting up anti-debugging bypass...");
    
    try {
        // Hook ptrace if available
        var ptrace = Module.findExportByName(null, "ptrace");
        if (ptrace && !ptrace.isNull()) {
            Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
                console.log("[PTRACE] Blocked ptrace call: " + request);
                return 0;
            }, 'int', ['int', 'int', 'pointer', 'pointer']));
            console.log("[✅] Ptrace hook installed");
        } else {
            console.log("[ℹ️] Ptrace not found, skipping");
        }
    } catch (e) {
        console.log("[⚠️] Ptrace hook failed: " + e.message);
    }
    
    console.log("[✅] Anti-debugging bypass complete");
}

// Network interception for URLSession
function interceptNetworkTraffic() {
    console.log("[🌐] Setting up network traffic interception...");
    
    try {
        // Hook NSURLSessionDataTask
        var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
        if (NSURLSessionDataTask) {
            Interceptor.attach(NSURLSessionDataTask['- resume'].implementation, {
                onEnter: function(args) {
                    try {
                        var task = new ObjC.Object(args[0]);
                        var request = task.currentRequest();
                        
                        if (request) {
                            var url = request.URL().absoluteString().toString();
                            var method = request.HTTPMethod().toString();
                            var headers = request.allHTTPHeaderFields();
                            
                            console.log("\n[📡] NETWORK REQUEST INTERCEPTED");
                            console.log("URL: " + url);
                            console.log("Method: " + method);
                            
                            // Extract and log headers
                            if (headers) {
                                var headerDict = {};
                                var headerKeys = headers.allKeys();
                                for (var i = 0; i < headerKeys.count(); i++) {
                                    var key = headerKeys.objectAtIndex_(i).toString();
                                    var value = headers.objectForKey_(key).toString();
                                    headerDict[key] = value;
                                    
                                    // Look for authentication tokens
                                    if (key.toLowerCase().includes('auth') || 
                                        key.toLowerCase().includes('token') ||
                                        key.toLowerCase().includes('bearer') ||
                                        key.toLowerCase().includes('session') ||
                                        key.toLowerCase().includes('posh') ||
                                        key.toLowerCase().includes('x-')) {
                                        console.log("🔑 AUTH HEADER: " + key + " = " + value);
                                        authTokens.push(key + ": " + value);
                                    }
                                }
                                
                                console.log("Headers: " + JSON.stringify(headerDict, null, 2));
                            }
                            
                            // Extract body if POST/PUT
                            if (method === "POST" || method === "PUT") {
                                var body = request.HTTPBody();
                                if (body) {
                                    try {
                                        var bodyData = new ObjC.Object(body);
                                        var bodyString = bodyData.toString();
                                        console.log("Body: " + bodyString);
                                    } catch (e) {
                                        console.log("Body: [Binary data]");
                                    }
                                }
                            }
                            
                            // Store API call
                            apiCalls.push({
                                timestamp: new Date().toISOString(),
                                method: method,
                                url: url,
                                headers: headerDict
                            });
                            
                            discoveredEndpoints.push(url);
                            
                            console.log("==================================================");
                        }
                    } catch (e) {
                        console.log("[⚠️] Error processing request: " + e.message);
                    }
                }
            });
            console.log("[✅] NSURLSessionDataTask hook installed");
        } else {
            console.log("[⚠️] NSURLSessionDataTask not found");
        }
    } catch (e) {
        console.log("[⚠️] Network interception failed: " + e.message);
    }
    
    console.log("[✅] Network interception setup complete");
}

// Hook authentication-related methods
function interceptAuthentication() {
    console.log("[🔐] Setting up authentication interception...");
    
    try {
        // Search for relevant classes
        var relevantClasses = [];
        for (var className in ObjC.classes) {
            if (className.toLowerCase().includes('posh') || 
                className.toLowerCase().includes('auth') ||
                className.toLowerCase().includes('login') ||
                className.toLowerCase().includes('session') ||
                className.toLowerCase().includes('token')) {
                relevantClasses.push(className);
                console.log("[🎯] Found relevant class: " + className);
            }
        }
        
        // Hook UserDefaults for token storage
        setTimeout(function() {
            try {
                var NSUserDefaults = ObjC.classes.NSUserDefaults;
                if (NSUserDefaults) {
                    Interceptor.attach(NSUserDefaults['- setObject:forKey:'].implementation, {
                        onEnter: function(args) {
                            try {
                                var key = new ObjC.Object(args[3]).toString();
                                var value = new ObjC.Object(args[2]).toString();
                                
                                if (key.toLowerCase().includes('token') || 
                                    key.toLowerCase().includes('auth') ||
                                    key.toLowerCase().includes('session') ||
                                    key.toLowerCase().includes('user') ||
                                    key.toLowerCase().includes('posh')) {
                                    console.log("[💾] UserDefaults Auth: " + key + " = " + value.substring(0, 100));
                                    authTokens.push(key + ": " + value);
                                }
                            } catch (e) {
                                console.log("[💾] UserDefaults activity detected");
                            }
                        }
                    });
                    console.log("[✅] UserDefaults hook installed");
                }
            } catch (e) {
                console.log("[⚠️] UserDefaults hook failed: " + e.message);
            }
        }, 1000);
        
    } catch (e) {
        console.log("[⚠️] Authentication interception failed: " + e.message);
    }
    
    console.log("[✅] Authentication hooks setup complete");
}

// Hook JSON parsing to extract API responses
function interceptJSONParsing() {
    console.log("[📝] Setting up JSON response interception...");
    
    try {
        var NSJSONSerialization = ObjC.classes.NSJSONSerialization;
        if (NSJSONSerialization) {
            Interceptor.attach(NSJSONSerialization['+ JSONObjectWithData:options:error:'].implementation, {
                onEnter: function(args) {
                    this.jsonData = args[2];
                },
                onLeave: function(retval) {
                    if (retval.toInt32() !== 0) {
                        try {
                            var jsonObject = new ObjC.Object(retval);
                            var jsonString = jsonObject.description().toString();
                            
                            // Look for interesting data in JSON responses
                            if (jsonString.includes('token') || 
                                jsonString.includes('auth') ||
                                jsonString.includes('session') ||
                                jsonString.includes('user') ||
                                jsonString.includes('price') ||
                                jsonString.includes('product') ||
                                jsonString.includes('posh')) {
                                console.log("\n[📊] INTERESTING JSON RESPONSE:");
                                console.log(jsonString.substring(0, 1000) + (jsonString.length > 1000 ? "..." : ""));
                                
                                // Extract tokens from JSON
                                var tokenRegex = /"[^"]*token[^"]*":\s*"([^"]+)"/gi;
                                var match;
                                while ((match = tokenRegex.exec(jsonString)) !== null) {
                                    console.log("🔑 JSON Token: " + match[0]);
                                    authTokens.push("json_token: " + match[0]);
                                }
                            }
                        } catch (e) {
                            // Silent fail for invalid JSON
                        }
                    }
                }
            });
            console.log("[✅] JSON interception hook installed");
        }
    } catch (e) {
        console.log("[⚠️] JSON interception failed: " + e.message);
    }
    
    console.log("[✅] JSON interception setup complete");
}

// Search for Poshmark-specific API patterns
function searchPoshmarkPatterns() {
    console.log("[🎯] Searching for Poshmark-specific patterns...");
    
    try {
        // Hook URL construction methods
        var NSURL = ObjC.classes.NSURL;
        if (NSURL) {
            Interceptor.attach(NSURL['+ URLWithString:'].implementation, {
                onEnter: function(args) {
                    try {
                        var urlString = new ObjC.Object(args[2]).toString();
                        if (urlString.includes('poshmark') || 
                            urlString.includes('api') ||
                            urlString.includes('posh')) {
                            console.log("[🔗] URL Construction: " + urlString);
                            discoveredEndpoints.push(urlString);
                        }
                    } catch (e) {
                        // Silent continue
                    }
                }
            });
            console.log("[✅] URL construction hook installed");
        }
    } catch (e) {
        console.log("[⚠️] Pattern search failed: " + e.message);
    }
    
    console.log("[✅] Pattern search setup complete");
}

// Generate comprehensive report
function generateReport() {
    console.log("\n" + "================================================================================");
    console.log("📊 POSHMARK REVERSE ENGINEERING SUMMARY REPORT");
    console.log("================================================================================");
    
    // Remove duplicates
    var uniqueEndpoints = [];
    for (var i = 0; i < discoveredEndpoints.length; i++) {
        if (uniqueEndpoints.indexOf(discoveredEndpoints[i]) === -1) {
            uniqueEndpoints.push(discoveredEndpoints[i]);
        }
    }
    
    var uniqueTokens = [];
    for (var i = 0; i < authTokens.length; i++) {
        if (uniqueTokens.indexOf(authTokens[i]) === -1) {
            uniqueTokens.push(authTokens[i]);
        }
    }
    
    console.log("\n🔗 DISCOVERED API ENDPOINTS (" + uniqueEndpoints.length + " total):");
    for (var i = 0; i < uniqueEndpoints.length; i++) {
        console.log("  " + (i + 1) + ". " + uniqueEndpoints[i]);
    }
    
    console.log("\n🔑 EXTRACTED AUTHENTICATION DATA (" + uniqueTokens.length + " tokens):");
    for (var i = 0; i < uniqueTokens.length; i++) {
        var token = uniqueTokens[i];
        console.log("  " + (i + 1) + ". " + token.substring(0, 100) + (token.length > 100 ? "..." : ""));
    }
    
    console.log("\n📡 API CALL SUMMARY:");
    console.log("  Total API calls intercepted: " + apiCalls.length);
    
    var methodCounts = {};
    for (var i = 0; i < apiCalls.length; i++) {
        var method = apiCalls[i].method;
        methodCounts[method] = (methodCounts[method] || 0) + 1;
    }
    
    var methods = Object.keys(methodCounts);
    for (var i = 0; i < methods.length; i++) {
        var method = methods[i];
        console.log("  " + method + ": " + methodCounts[method] + " calls");
    }
    
    console.log("\n✅ REVERSE ENGINEERING COMPLETE");
    console.log("🚀 Ready for Python automation script generation");
    console.log("================================================================================");
}

// Manual control functions
rpc.exports = {
    generateReport: generateReport,
    showTokens: function() {
        console.log("🔑 Current Tokens:");
        for (var i = 0; i < authTokens.length; i++) {
            console.log("  " + (i + 1) + ". " + authTokens[i]);
        }
    },
    showEndpoints: function() {
        console.log("🔗 Current Endpoints:");
        for (var i = 0; i < discoveredEndpoints.length; i++) {
            console.log("  " + (i + 1) + ". " + discoveredEndpoints[i]);
        }
    },
    getApiCalls: function() {
        return apiCalls;
    },
    getTokens: function() {
        return authTokens;
    },
    getEndpoints: function() {
        return discoveredEndpoints;
    }
};

// Main execution
function main() {
    console.log("[🚀] Initializing Poshmark reverse engineering...");
    
    // Execute all interception techniques
    bypassAntiDebugging();
    interceptNetworkTraffic();
    interceptAuthentication();
    interceptJSONParsing();
    searchPoshmarkPatterns();
    
    console.log("[✅] All hooks installed successfully");
    console.log("[📱] Please interact with the Poshmark app now...");
    console.log("[⏰] Analysis will run continuously...");
    
    // Auto-generate report after 30 seconds of activity
    setTimeout(function() {
        if (apiCalls.length > 0) {
            generateReport();
        } else {
            console.log("[⚠️] No API calls detected yet. Continue using the app...");
            console.log("[💡] Try: Login, browse products, search items, view profiles");
        }
    }, 30000);
    
    // Generate report every 60 seconds if there's activity
    setInterval(function() {
        if (apiCalls.length > 0) {
            console.log("\n[🔄] Generating updated report...");
            generateReport();
        }
    }, 60000);
}

// Start the main process
main();