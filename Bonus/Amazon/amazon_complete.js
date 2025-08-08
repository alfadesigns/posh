// Amazon Network Traffic Sniffer - Fixed Version
console.log("[*] Amazon Analysis Script Loaded...");

// ========== SSL PINNING BYPASS ==========
console.log("[*] Setting up SSL bypass...");

if (ObjC.available) {
    // Method 1: SecTrustEvaluate bypass
    try {
        var SecTrustEvaluate = Module.findExportByName('Security', 'SecTrustEvaluate');
        if (SecTrustEvaluate) {
            Interceptor.replace(SecTrustEvaluate, new NativeCallback(function(trust, result) {
                console.log('[SSL] Trust evaluation bypassed');
                if (result) {
                    Memory.writeU8(result, 1); // kSecTrustResultProceed
                }
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'pointer']));
            console.log('[SSL] SecTrustEvaluate hooked');
        }
    } catch(e) {
        console.log('[SSL] SecTrustEvaluate hook failed: ' + e);
    }

    // Method 2: SSL Context bypass
    try {
        var SSLSetSessionOption = Module.findExportByName('Security', 'SSLSetSessionOption');
        if (SSLSetSessionOption) {
            Interceptor.replace(SSLSetSessionOption, new NativeCallback(function(context, option, value) {
                console.log('[SSL] SSLSetSessionOption bypassed');
                return 0; // errSecSuccess
            }, 'int', ['pointer', 'int', 'int']));
            console.log('[SSL] SSLSetSessionOption hooked');
        }
    } catch(e) {
        console.log('[SSL] SSLSetSessionOption hook failed: ' + e);
    }
}

// ========== NETWORK TRAFFIC CAPTURE ==========
var requestCounter = 0;

if (ObjC.available) {
    console.log("[*] Setting up network hooks...");
    
    // Hook NSURLSessionDataTask
    try {
        var NSURLSessionDataTask = ObjC.classes.NSURLSessionDataTask;
        if (NSURLSessionDataTask) {
            var originalResume = NSURLSessionDataTask['- resume'];
            Interceptor.attach(originalResume.implementation, {
                onEnter: function(args) {
                    try {
                        var task = new ObjC.Object(args[0]);
                        var request = task.currentRequest();
                        
                        if (request) {
                            requestCounter++;
                            var url = request.URL().absoluteString().toString();
                            var method = request.HTTPMethod();
                            var methodStr = method ? method.toString() : 'GET';
                            var headers = request.allHTTPHeaderFields();
                            
                            console.log("\n" + "=".repeat(60));
                            console.log(`[REQUEST #${requestCounter}] ${new Date().toISOString()}`);
                            console.log(`[METHOD] ${methodStr}`);
                            console.log(`[URL] ${url}`);
                            
                            if (headers) {
                                console.log(`[HEADERS] ${headers.toString()}`);
                            }
                            
                            // Try to get request body
                            try {
                                var body = request.HTTPBody();
                                if (body) {
                                    console.log(`[BODY] ${body.toString()}`);
                                }
                            } catch(e) {
                                // Body might not be accessible
                            }
                            
                            // Store for response correlation
                            this.requestId = requestCounter;
                            this.requestUrl = url;
                        }
                    } catch(e) {
                        console.log(`[ERROR] Request hook error: ${e}`);
                    }
                }
            });
            console.log("[*] NSURLSessionDataTask hooked");
        }
    } catch(e) {
        console.log(`[ERROR] NSURLSessionDataTask hook failed: ${e}`);
    }

    // Hook NSURLConnection (legacy support)
    try {
        var NSURLConnection = ObjC.classes.NSURLConnection;
        if (NSURLConnection) {
            var sendSyncRequest = NSURLConnection['+ sendSynchronousRequest:returningResponse:error:'];
            if (sendSyncRequest) {
                Interceptor.attach(sendSyncRequest.implementation, {
                    onEnter: function(args) {
                        try {
                            var request = new ObjC.Object(args[2]);
                            var url = request.URL().absoluteString().toString();
                            var method = request.HTTPMethod().toString();
                            
                            console.log("\n[LEGACY_REQUEST]");
                            console.log(`[METHOD] ${method}`);
                            console.log(`[URL] ${url}`);
                        } catch(e) {
                            console.log(`[ERROR] Legacy request error: ${e}`);
                        }
                    }
                });
                console.log("[*] NSURLConnection hooked");
            }
        }
    } catch(e) {
        console.log(`[ERROR] NSURLConnection hook failed: ${e}`);
    }
}

// ========== FIND AMAZON CLASSES ==========
console.log("[*] Searching for Amazon classes...");

if (ObjC.available) {
    try {
        var allClasses = Object.keys(ObjC.classes);
        var amazonClasses = allClasses.filter(name => 
            name.toLowerCase().includes('amazon') || 
            name.includes('AMZ') || 
            name.toLowerCase().includes('auth') ||
            name.toLowerCase().includes('network')
        );
        
        console.log(`[*] Found ${amazonClasses.length} relevant classes:`);
        amazonClasses.slice(0, 20).forEach((className, index) => {
            console.log(`[${index + 1}] ${className}`);
        });
        
    } catch(e) {
        console.log(`[ERROR] Class enumeration failed: ${e}`);
    }
}

console.log("\n[*] Setup complete!");
console.log("[*] Use Amazon app now - all network traffic will be logged");
console.log("[*] SSL bypass active");
console.log("=".repeat(60));