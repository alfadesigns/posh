#!/usr/bin/env python3
"""
Amazon Laptop Pricing Extractor - Deep Data Mining
Specifically targets buyingOptions and pricing fields from product APIs
Author: Suhaib Alfageeh
"""

import requests
import json
from datetime import datetime

class LaptopPricingExtractor:
    def __init__(self, access_token, session_id, ubid, marketplace_id="ATVPDKIKX0DER"):
        self.access_token = access_token
        self.session_id = session_id
        self.ubid = ubid
        self.marketplace_id = marketplace_id
        
        self.base_headers = {
            'User-Agent': 'Amazon/569636.0 CFNetwork/1406.0.4 Darwin/22.4.0',
            'Accept-Language': 'en-US,en;q=0.9',
            'x-amz-access-token': self.access_token,
            'X-Amzn-Session-Id': self.session_id,
            'X-Amzn-UBID': self.ubid,
        }
        
        self.data_api_headers = {
            **self.base_headers,
            'Cookie': self._build_cookie_string(),
        }
    
    def _build_cookie_string(self):
        return (
            f"session-id={self.session_id}; "
            f"ubid-main={self.ubid}; "
            "lc-main=en_US; "
            "i18n-prefs=USD; "
            "amzn-app-id=Amazon/21.17.0/1-569636.0; "
            "search-network-type=wifi"
        )
    
    def _generate_signature(self):
        timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S-0400")
        return f"HmacSHA256 Time={timestamp} SignedHeaders=accept;accept-language;x-amz-access-token;x-amzn-app-id;x-amzn-lob;x-amzn-session-id Signature=a1b2c3d4e5f6789012345678901234567890abcdef/1234567890abcdef"
    
    def extract_laptop_pricing(self, asin):
        """Extract detailed pricing from buyingOptions field"""
        print(f"\n💰 EXTRACTING LAPTOP PRICING FOR {asin}")
        print("=" * 60)
        
        url = f"https://data.amazon.com/api/marketplaces/{self.marketplace_id}/products/{asin}"
        
        headers = {
            **self.data_api_headers,
            'Accept': 'application/vnd.com.amazon.api+json; type="collection(product/v2)/v1"; expand="productImages(product.product-images/v2)"',
            'x-amzn-app-id': 'name=replenishment-metab-ingress,version=21.17.0,build=2.0.6145.0',
            'x-amzn-lob': '1'
        }
        
        headers['x-aapi-signature'] = self._generate_signature()
        
        try:
            response = requests.get(url, headers=headers)
            print(f"[PRICING API] {response.status_code} - {len(response.content)} bytes")
            
            if response.status_code == 200:
                data = response.json()
                return self._deep_mine_pricing_data(data, asin)
            else:
                print(f"API Error: {response.status_code}")
                return None
                
        except Exception as e:
            print(f"API Exception: {e}")
            return None
    
    def _deep_mine_pricing_data(self, data, asin):
        """Deep mine all pricing data from the response"""
        print(f"\n🔍 DEEP MINING PRICING DATA:")
        print("-" * 40)
        
        # Print the entire response to see what's actually there
        print(f"FULL API RESPONSE:")
        print(json.dumps(data, indent=2))
        
        pricing_data = {}
        
        # Focus on entities and buyingOptions
        if 'entities' in data and isinstance(data['entities'], list):
            for i, entity in enumerate(data['entities']):
                print(f"\n📦 ENTITY {i+1} DETAILED ANALYSIS:")
                
                if isinstance(entity, dict) and 'entity' in entity:
                    product_entity = entity['entity']
                    
                    # Extract ASIN
                    if 'asin' in product_entity:
                        pricing_data['asin'] = product_entity['asin']
                        print(f"  ASIN: {product_entity['asin']}")
                    
                    # CRITICAL: Extract buyingOptions (this should contain pricing!)
                    if 'buyingOptions' in product_entity:
                        buying_options = product_entity['buyingOptions']
                        print(f"\n  🛒 BUYING OPTIONS (PRICING DATA):")
                        print(f"     Type: {type(buying_options)}")
                        print(f"     Content: {json.dumps(buying_options, indent=4)}")
                        
                        # Mine pricing from buyingOptions
                        pricing_extracted = self._extract_pricing_from_buying_options(buying_options)
                        if pricing_extracted:
                            pricing_data.update(pricing_extracted)
                    
                    # Extract productImages data
                    if 'productImages' in product_entity:
                        product_images = product_entity['productImages']
                        print(f"\n  🖼️ PRODUCT IMAGES:")
                        print(f"     Type: {type(product_images)}")
                        if isinstance(product_images, dict):
                            for key, value in product_images.items():
                                if key != 'metadata':  # Skip metadata, focus on actual data
                                    print(f"     {key}: {value}")
        
        # Search for any pricing patterns in the entire response
        all_pricing = self._find_all_pricing_patterns(data)
        if all_pricing:
            print(f"\n💵 ALL PRICING PATTERNS FOUND:")
            for pattern_type, values in all_pricing.items():
                print(f"  {pattern_type}: {values}")
                pricing_data[pattern_type] = values
        
        return pricing_data
    
    def _extract_pricing_from_buying_options(self, buying_options):
        """Extract pricing specifically from buyingOptions field"""
        pricing = {}
        
        if isinstance(buying_options, dict):
            for key, value in buying_options.items():
                print(f"    buyingOptions.{key}: {value}")
                
                # Look for common pricing fields
                if any(price_term in key.lower() for price_term in ['price', 'cost', 'amount', 'value']):
                    pricing[f"buying_options_{key}"] = value
                
                # If value is a dict, search deeper
                if isinstance(value, dict):
                    nested_pricing = self._search_nested_pricing(value, f"buyingOptions.{key}")
                    pricing.update(nested_pricing)
                
                # If value is a list, check each item
                elif isinstance(value, list):
                    for i, item in enumerate(value):
                        if isinstance(item, dict):
                            nested_pricing = self._search_nested_pricing(item, f"buyingOptions.{key}[{i}]")
                            pricing.update(nested_pricing)
        
        elif isinstance(buying_options, list):
            for i, option in enumerate(buying_options):
                if isinstance(option, dict):
                    nested_pricing = self._search_nested_pricing(option, f"buyingOptions[{i}]")
                    pricing.update(nested_pricing)
        
        return pricing
    
    def _search_nested_pricing(self, data, path):
        """Recursively search for pricing in nested structures"""
        pricing = {}
        
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = f"{path}.{key}"
                
                # Check for pricing keywords
                if any(term in key.lower() for term in ['price', 'cost', 'amount', 'value', 'total', 'subtotal']):
                    pricing[current_path] = value
                    print(f"    💰 FOUND PRICING: {current_path} = {value}")
                
                # Check for currency symbols in strings
                if isinstance(value, str):
                    import re
                    if re.search(r'\$[\d,]+\.?\d*|[\d,]+\.?\d*\s*(USD|usd)', value):
                        pricing[f"{current_path}_currency"] = value
                        print(f"    💵 FOUND CURRENCY: {current_path} = {value}")
                
                # Recursive search
                elif isinstance(value, (dict, list)):
                    nested = self._search_nested_pricing(value, current_path)
                    pricing.update(nested)
        
        elif isinstance(data, list):
            for i, item in enumerate(data):
                current_path = f"{path}[{i}]"
                nested = self._search_nested_pricing(item, current_path)
                pricing.update(nested)
        
        return pricing
    
    def _find_all_pricing_patterns(self, data, path=""):
        """Find all possible pricing patterns in the entire response"""
        patterns = {
            'dollar_amounts': [],
            'numeric_prices': [],
            'currency_codes': [],
            'pricing_fields': []
        }
        
        def search_recursive(obj, current_path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    new_path = f"{current_path}.{key}" if current_path else key
                    
                    # Check field names for pricing indicators
                    if any(term in key.lower() for term in ['price', 'cost', 'amount', 'value', 'total']):
                        patterns['pricing_fields'].append({
                            'path': new_path,
                            'value': value
                        })
                    
                    # Check string values for currency patterns
                    if isinstance(value, str):
                        import re
                        dollar_matches = re.findall(r'\$[\d,]+\.?\d*', value)
                        if dollar_matches:
                            patterns['dollar_amounts'].extend(dollar_matches)
                        
                        if value in ['USD', 'usd', 'EUR', 'GBP']:
                            patterns['currency_codes'].append(value)
                    
                    # Check numeric values that could be prices
                    elif isinstance(value, (int, float)) and 0.01 <= value <= 10000:
                        if any(term in key.lower() for term in ['price', 'cost', 'amount', 'value']):
                            patterns['numeric_prices'].append({
                                'path': new_path,
                                'value': value
                            })
                    
                    # Recursive search
                    elif isinstance(value, (dict, list)):
                        search_recursive(value, new_path)
            
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    new_path = f"{current_path}[{i}]" if current_path else f"[{i}]"
                    search_recursive(item, new_path)
        
        search_recursive(data)
        
        # Remove empty patterns
        return {k: v for k, v in patterns.items() if v}

def main():
    """Extract laptop pricing from discovered ASINs"""
    print("💰 AMAZON LAPTOP PRICING EXTRACTOR")
    print("🎯 DEEP MINING FOR ACTUAL PRICING DATA")
    print("=" * 60)
    
    extractor = LaptopPricingExtractor(
        access_token="Atna|EwICICeI-lv6F7BknNiUNNpaBeqKwNpXNQiHILkAu-sBmTFFwmLcYjmSlQTVUAXS5SI8QRHgnYip71VSoDqaVK7l3nEAQDOdcJcBghiQos_nvEXSxNUBUIx3qu6zCDhEezlfx2VtvMelXgfxtTmXmo4ZAYnQ0am9lGvO_2mMwNkJJvLtcM65pm49XX-RO8G6F4tbAa3u5IT07fdItv0zNCeXNTPCc5_EZ-JgHeI6cvb8lZgAKpbmcZa-IPaWDtQDm_NXycAdNeX6G53_zvTad037uZbtJKiMXjZmNQymzbgEUWrUwuP3wf1Xhv7_VTfJk298iCP_TdX81dDBPtQI8NjNwSag",
        session_id="133-1970838-2548066",
        ubid="135-1955395-3065514"
    )
    
    # These are the discovered laptop ASINs from your traffic analysis
    laptop_asins = ["B0949CSB9X", "B0FFNJJN2V", "B0DSQB6Y29"]
    
    all_pricing_data = {}
    
    for asin in laptop_asins:
        pricing_data = extractor.extract_laptop_pricing(asin)
        if pricing_data:
            all_pricing_data[asin] = pricing_data
        
        print("\n" + "="*60)
    
    # Final summary
    print(f"\n🎯 LAPTOP PRICING EXTRACTION SUMMARY:")
    print("=" * 50)
    
    total_pricing_fields = sum(len(data) for data in all_pricing_data.values())
    print(f"✅ Laptops analyzed: {len(laptop_asins)}")
    print(f"✅ Pricing fields discovered: {total_pricing_fields}")
    
    for asin, pricing in all_pricing_data.items():
        print(f"\n📱 {asin}:")
        if pricing:
            for field, value in pricing.items():
                print(f"   💰 {field}: {value}")
        else:
            print(f"   ⚠️ No pricing data extracted (may need different API endpoint)")
    
    if not any(all_pricing_data.values()):
        print(f"\n💡 NEXT STEPS:")
        print(f"   • buyingOptions may require additional API calls")
        print(f"   • Try different API endpoints (e.g., /pricing, /offers)")
        print(f"   • May need to trigger pricing APIs through search/browse actions")
        print(f"   • Consider capturing traffic during actual product purchases")

if __name__ == "__main__":
    main()