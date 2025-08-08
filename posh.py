#!/usr/bin/env python3
"""
Enhanced Poshmark Competitive Intelligence System
Complete API automation with robust pricing analysis
Author: Suhaib Alfageeh
Target: Poshmark iOS Application - Enhanced for Pricing Team Requirements
"""

import requests
import json
import time
from datetime import datetime
import re
from urllib.parse import urlencode, quote_plus
import base64
import hashlib
import statistics
from collections import defaultdict

class PoshmarkCompetitiveIntelligence:
    def __init__(self):
        """Initialize Poshmark API client with extracted credentials"""
        
        # Authentication tokens extracted from Frida
        self.oauth_token = "2344bfde01bd74cf93ae0abe09a2454528ec4d9d7b808aee4867b3ce84bdfe1e"
        self.auth_session_id = "689535a08102a282ae40019c"
        self.user_id = "689531883972a87025962ead"
        self.visitor_id = "68953161f1e0c00683a66759"
        self.device_id = "ios2:bf26e347b4eb6892eed643d679c5e3cb"
        
        # Base API configuration
        self.api_base = "https://api.poshmark.com/api"
        self.tracking_base = "https://et.poshmark.com"
        self.image_base = "https://di2ponv0v5otw.cloudfront.net"
        
        # Core headers extracted from traffic analysis
        self.base_headers = {
            'User-Agent': 'Poshmark/9.28 (iPhone13,2; iOS 16.4; Scale/3.00) Alamofire/5.10.2',
            'Accept-Language': 'en-US;q=1.0, ar-US;q=0.9',
            'Accept-Encoding': 'br;q=1.0, gzip;q=0.9, deflate;q=0.8',
            'X-HTTP_AUTHORIZATION': f'oauth {self.oauth_token}',
        }
        
        # API parameters consistently used
        self.common_params = {
            'api_version': '0.2',
            'app_version': '9.28',
            'app_type': 'iphone',
            'app_state': 'acv',
            'home_domain': 'us',
            'domain': 'us',
            'format': 'json',
            'gst': 'false',
            'exp': 'all',
            'base_exp': 'all',
            'auth_session_id': self.auth_session_id,
            'visitor_id': self.visitor_id,
            'device_id': self.device_id
        }
        
        # Enhanced data storage for competitive intelligence
        self.extracted_data = {
            'products': [],
            'pricing_analytics': {
                'by_category': defaultdict(list),
                'by_brand': defaultdict(list),
                'by_condition': defaultdict(list),
                'discount_patterns': []
            },
            'market_trends': [],
            'competitor_insights': {},
            'brand_analytics': {},
            'api_responses': []
        }
        
        # Rate limiting
        self.last_request_time = 0
        self.request_delay = 0.5  # 500ms between requests
        
    def _make_request(self, method, url, headers=None, params=None, data=None):
        """Make rate-limited API request with proper error handling"""
        
        # Rate limiting
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.request_delay:
            time.sleep(self.request_delay - time_since_last)
        
        # Merge headers
        request_headers = {**self.base_headers}
        if headers:
            request_headers.update(headers)
        
        # Merge params
        request_params = {**self.common_params}
        if params:
            request_params.update(params)
        
        try:
            print(f"🌐 {method} {url}")
            print(f"📋 Params: {list(request_params.keys())}")
            
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                params=request_params,
                data=data,
                timeout=10
            )
            
            self.last_request_time = time.time()
            
            # Log the request for analysis
            self._log_api_call(method, url, response.status_code, len(response.content))
            
            print(f"📊 Response: {response.status_code} - {len(response.content)} bytes")
            
            if response.status_code == 200:
                try:
                    json_data = response.json()
                    return json_data
                except json.JSONDecodeError as e:
                    print(f"⚠️ JSON decode error: {e}")
                    print(f"📄 Raw response (first 200 chars): {response.text[:200]}")
                    return None
            else:
                print(f"⚠️ API Error: {response.status_code}")
                print(f"📄 Error response: {response.text[:200]}")
                return None
                
        except Exception as e:
            print(f"❌ Request failed: {e}")
            return None
    
    def _safe_float(self, value, default=0.0):
        """Safely convert value to float"""
        if value is None:
            return default
        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
                # Remove any currency symbols or formatting
                cleaned = re.sub(r'[^\d.-]', '', str(value))
                return float(cleaned) if cleaned else default
            else:
                return default
        except (ValueError, TypeError):
            return default
    
    def _safe_int(self, value, default=0):
        """Safely convert value to int"""
        if value is None:
            return default
        try:
            if isinstance(value, (int, float)):
                return int(value)
            elif isinstance(value, str):
                cleaned = re.sub(r'[^\d-]', '', str(value))
                return int(cleaned) if cleaned else default
            else:
                return default
        except (ValueError, TypeError):
            return default
    
    def _log_api_call(self, method, url, status_code, response_size):
        """Log API call for analysis"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'url': url,
            'status_code': status_code,
            'response_size': response_size
        }
        self.extracted_data['api_responses'].append(log_entry)
    
    def search_products(self, query, max_results=48):
        """Search for products using the discovered search API"""
        print(f"\n🔍 SEARCHING PRODUCTS: '{query}'")
        print("-" * 50)
        
        # First get search suggestions (exactly as captured)
        suggestions_url = f"{self.api_base}/searches/suggested"
        suggestions_params = {
            'query': query,
            'count': 20,
            'for_user_id': self.user_id
        }
        
        suggestions = self._make_request('GET', suggestions_url, params=suggestions_params)
        
        if suggestions:
            suggestion_data = suggestions.get('data', [])
            print(f"✅ Found {len(suggestion_data)} search suggestions")
            
            if suggestion_data:
                print(f"🔍 Sample suggestion structure: {list(suggestion_data[0].keys()) if suggestion_data else 'None'}")
                for i, suggestion in enumerate(suggestion_data[:5]):
                    display_text = suggestion.get('kw') or suggestion.get('display') or suggestion.get('title') or suggestion.get('text') or str(suggestion)
                    print(f"  {i+1}. {display_text}")
        
        # Main product search (exact URL pattern from capture)
        search_url = f"{self.api_base}/posts"
        search_params = {
            'request': json.dumps({
                'filters': {'inventory_status': ['available']},
                'query': query
            }),
            'nm': 'sl_all',
            'summarize': 'true',
            'src': 'dir',
            'end_of_search_v2': 'true',
            'suggested_filters_count': 40
        }
        
        print(f"🔄 Making search request to: {search_url}")
        products_data = self._make_request('GET', search_url, params=search_params)
        
        products = []
        
        if products_data:
            print(f"✅ Products API Response received")
            print(f"🔍 Response structure: {list(products_data.keys())}")
            
            # The API returns products directly in 'data' array
            if 'data' in products_data:
                data_items = products_data['data']
                print(f"📊 Data items found: {len(data_items)}")
                
                if data_items:
                    first_item = data_items[0]
                    print(f"🔍 First item structure: {list(first_item.keys())[:10]}...")
                    
                    # Extract products directly from data array
                    for product in data_items[:max_results]:
                        product_info = self._extract_product_details(product)
                        if product_info:
                            products.append(product_info)
                            self.extracted_data['products'].append(product_info)
                            
                            # Store pricing analytics by category
                            category = product_info.get('category', 'unknown')
                            brand = product_info.get('brand', 'unknown')
                            condition = product_info.get('condition', 'unknown')
                            
                            if product_info.get('current_price', 0) > 0:
                                self.extracted_data['pricing_analytics']['by_category'][category].append(product_info['current_price'])
                                self.extracted_data['pricing_analytics']['by_brand'][brand].append(product_info['current_price'])
                                self.extracted_data['pricing_analytics']['by_condition'][condition].append(product_info['current_price'])
                            
                            # Store discount patterns
                            if product_info.get('discount_percent', 0) > 0:
                                self.extracted_data['pricing_analytics']['discount_patterns'].append({
                                    'category': category,
                                    'brand': brand,
                                    'discount_percent': product_info['discount_percent'],
                                    'original_price': product_info.get('original_price', 0),
                                    'current_price': product_info.get('current_price', 0)
                                })
            
            print(f"🛍️ Successfully extracted {len(products)} products")
            
            # Show sample product for debugging
            if products:
                sample = products[0]
                price_display = f"${sample.get('current_price', 'N/A')}" if sample.get('current_price') else 'N/A'
                print(f"📦 Sample product: {sample.get('title', 'N/A')} - {price_display}")
            
            return products
        else:
            print("❌ No product data received from API")
            return []
    
    def _extract_product_details(self, product_data):
        """Extract competitive intelligence from product data with robust pricing"""
        try:
            product_info = {
                'id': product_data.get('id', 'N/A'),
                'title': product_data.get('title', 'N/A'),
                'brand': product_data.get('brand', 'N/A'),
                'size': product_data.get('size_obj', {}).get('display', product_data.get('size', 'N/A')),
                'condition': product_data.get('condition', 'N/A'),
                'timestamp': datetime.now().isoformat(),
                'category': product_data.get('category', 'N/A'),
                'department': product_data.get('department', 'N/A'),
            }
            
            # Extract pricing information with robust error handling
            current_price = 0
            original_price = 0
            currency = '$'
            
            # Current price extraction
            if 'price_amount' in product_data:
                price_data = product_data['price_amount']
                current_price = self._safe_float(price_data.get('val', 0))
                currency = price_data.get('currency_symbol', '$')
            elif 'price' in product_data:
                current_price = self._safe_float(product_data['price'])
            
            product_info['current_price'] = current_price
            product_info['currency'] = currency
            
            # Original price extraction
            if 'original_price_amount' in product_data:
                orig_price_data = product_data['original_price_amount']
                original_price = self._safe_float(orig_price_data.get('val', 0))
            elif 'original_price' in product_data:
                original_price = self._safe_float(product_data['original_price'])
            
            product_info['original_price'] = original_price
            
            # Calculate discount safely
            if original_price > 0 and current_price > 0 and original_price > current_price:
                discount = original_price - current_price
                discount_percent = (discount / original_price) * 100
                product_info['discount_amount'] = round(discount, 2)
                product_info['discount_percent'] = round(discount_percent, 2)
            else:
                product_info['discount_amount'] = 0
                product_info['discount_percent'] = 0
            
            # Extract engagement metrics from aggregates
            if 'aggregates' in product_data:
                aggregates = product_data['aggregates']
                product_info.update({
                    'likes': self._safe_int(aggregates.get('likes', 0)),
                    'comments': self._safe_int(aggregates.get('comments', 0)),
                    'shares': self._safe_int(aggregates.get('shares', 0)),
                })
            else:
                # Fallback to direct fields
                product_info.update({
                    'likes': self._safe_int(product_data.get('like_count', 0)),
                    'comments': self._safe_int(product_data.get('comment_count', 0)),
                    'shares': self._safe_int(product_data.get('share_count', 0)),
                })
            
            # Extract seller information
            product_info.update({
                'seller_username': product_data.get('creator_username', 'N/A'),
                'seller_display_name': product_data.get('creator_display_handle', 'N/A'),
            })
            
            # Extract image URLs
            if 'pictures' in product_data and product_data['pictures']:
                product_info['images'] = [
                    pic.get('url', '') for pic in product_data['pictures'][:3]
                ]
            elif 'picture_url' in product_data:
                product_info['images'] = [product_data['picture_url']]
            else:
                product_info['images'] = []
            
            return product_info
            
        except Exception as e:
            print(f"⚠️ Error extracting product: {e}")
            # Return minimal info even if extraction fails
            return {
                'id': product_data.get('id', 'N/A'),
                'title': product_data.get('title', 'N/A'),
                'current_price': 0,
                'error': str(e)
            }
    
    def competitive_price_monitoring(self, search_terms):
        """Enhanced competitive pricing analysis for pricing team requirements"""
        print(f"\n💰 ENHANCED COMPETITIVE PRICE MONITORING")
        print("=" * 60)
        
        all_pricing_data = []
        
        for term in search_terms:
            print(f"\n🔍 Analyzing: '{term}'")
            products = self.search_products(term, max_results=40)
            
            if products:
                # Extract valid prices
                prices = [p.get('current_price', 0) for p in products if p.get('current_price', 0) > 0]
                original_prices = [p.get('original_price', 0) for p in products if p.get('original_price', 0) > 0]
                discounts = [p.get('discount_percent', 0) for p in products if p.get('discount_percent', 0) > 0]
                
                if prices:
                    pricing_analysis = {
                        'search_term': term,
                        'product_count': len(products),
                        'price_statistics': {
                            'min': min(prices),
                            'max': max(prices),
                            'avg': round(statistics.mean(prices), 2),
                            'median': round(statistics.median(prices), 2),
                            'std_dev': round(statistics.stdev(prices) if len(prices) > 1 else 0, 2)
                        },
                        'pricing_distribution': self._analyze_price_distribution(prices),
                        'discount_analysis': {
                            'discounted_products': len(discounts),
                            'avg_discount': round(statistics.mean(discounts), 2) if discounts else 0,
                            'max_discount': max(discounts) if discounts else 0,
                            'discount_rate': round((len(discounts) / len(products)) * 100, 2)
                        },
                        'brand_insights': self._analyze_brand_pricing(products),
                        'condition_insights': self._analyze_condition_pricing(products),
                        'timestamp': datetime.now().isoformat()
                    }
                    
                    all_pricing_data.append(pricing_analysis)
                    
                    print(f"  📊 {len(products)} products analyzed")
                    print(f"  💵 Price range: ${pricing_analysis['price_statistics']['min']:.2f} - ${pricing_analysis['price_statistics']['max']:.2f}")
                    print(f"  📈 Average: ${pricing_analysis['price_statistics']['avg']:.2f} | Median: ${pricing_analysis['price_statistics']['median']:.2f}")
                    print(f"  🎯 Discount rate: {pricing_analysis['discount_analysis']['discount_rate']:.1f}%")
        
        self.extracted_data['market_trends'].extend(all_pricing_data)
        return all_pricing_data
    
    def _analyze_price_distribution(self, prices):
        """Analyze price distribution patterns"""
        if not prices:
            return {}
        
        # Define price ranges
        ranges = [
            (0, 25, "Budget"),
            (25, 50, "Low-Mid"),
            (50, 100, "Mid-Range"),
            (100, 200, "Premium"),
            (200, float('inf'), "Luxury")
        ]
        
        distribution = {}
        for min_price, max_price, label in ranges:
            count = len([p for p in prices if min_price <= p < max_price])
            distribution[label] = {
                'count': count,
                'percentage': round((count / len(prices)) * 100, 1)
            }
        
        return distribution
    
    def _analyze_brand_pricing(self, products):
        """Analyze pricing patterns by brand"""
        brand_data = defaultdict(list)
        
        for product in products:
            brand = product.get('brand', 'Unknown')
            price = product.get('current_price', 0)
            if price > 0:
                brand_data[brand].append(price)
        
        brand_insights = {}
        for brand, prices in brand_data.items():
            if len(prices) >= 2:  # Only analyze brands with multiple products
                brand_insights[brand] = {
                    'product_count': len(prices),
                    'avg_price': round(statistics.mean(prices), 2),
                    'price_range': [min(prices), max(prices)],
                    'std_dev': round(statistics.stdev(prices), 2)
                }
        
        return brand_insights
    
    def _analyze_condition_pricing(self, products):
        """Analyze pricing patterns by condition"""
        condition_data = defaultdict(list)
        
        for product in products:
            condition = product.get('condition', 'Unknown')
            price = product.get('current_price', 0)
            if price > 0:
                condition_data[condition].append(price)
        
        condition_insights = {}
        for condition, prices in condition_data.items():
            if prices:
                condition_insights[condition] = {
                    'product_count': len(prices),
                    'avg_price': round(statistics.mean(prices), 2),
                    'price_range': [min(prices), max(prices)]
                }
        
        return condition_insights
    
    def generate_pricing_intelligence_report(self):
        """Generate comprehensive pricing intelligence report for business team"""
        print(f"\n📊 PRICING INTELLIGENCE REPORT")
        print("=" * 70)
        
        report = {
            'report_timestamp': datetime.now().isoformat(),
            'executive_summary': self._generate_executive_summary(),
            'market_analysis': self.extracted_data['market_trends'],
            'competitive_landscape': self._analyze_competitive_landscape(),
            'pricing_recommendations': self._generate_pricing_recommendations(),
            'data_summary': {
                'total_products_analyzed': len(self.extracted_data['products']),
                'unique_brands': len(set(p.get('brand', 'N/A') for p in self.extracted_data['products'])),
                'price_points_analyzed': len([p for p in self.extracted_data['products'] if p.get('current_price', 0) > 0]),
                'categories_covered': len(set(p.get('category', 'N/A') for p in self.extracted_data['products'])),
                'api_calls_made': len(self.extracted_data['api_responses'])
            }
        }
        
        # Print executive summary
        print(f"🎯 EXECUTIVE SUMMARY:")
        for key, value in report['executive_summary'].items():
            print(f"  • {key}: {value}")
        
        print(f"\n📈 DATA COVERAGE:")
        for key, value in report['data_summary'].items():
            print(f"  📊 {key.replace('_', ' ').title()}: {value}")
        
        return report
    
    def _generate_executive_summary(self):
        """Generate executive summary of findings"""
        products = self.extracted_data['products']
        valid_prices = [p.get('current_price', 0) for p in products if p.get('current_price', 0) > 0]
        
        if not valid_prices:
            return {"status": "No pricing data available"}
        
        discounted_products = len([p for p in products if p.get('discount_percent', 0) > 0])
        
        return {
            'avg_market_price': f"${statistics.mean(valid_prices):.2f}",
            'price_range': f"${min(valid_prices):.2f} - ${max(valid_prices):.2f}",
            'discount_prevalence': f"{(discounted_products/len(products)*100):.1f}% of products discounted",
            'most_active_brand': self._get_most_active_brand(),
            'competitive_intensity': self._assess_competitive_intensity()
        }
    
    def _get_most_active_brand(self):
        """Get the brand with most products"""
        brand_counts = defaultdict(int)
        for product in self.extracted_data['products']:
            brand = product.get('brand', 'Unknown')
            if brand != 'N/A':
                brand_counts[brand] += 1
        
        if brand_counts:
            return max(brand_counts.items(), key=lambda x: x[1])[0]
        return "No brand data"
    
    def _assess_competitive_intensity(self):
        """Assess competitive intensity based on pricing patterns"""
        products = self.extracted_data['products']
        discounted = len([p for p in products if p.get('discount_percent', 0) > 0])
        
        if not products:
            return "No data"
        
        discount_rate = discounted / len(products)
        
        if discount_rate > 0.5:
            return "High (>50% products discounted)"
        elif discount_rate > 0.3:
            return "Moderate (30-50% products discounted)"
        else:
            return "Low (<30% products discounted)"
    
    def _analyze_competitive_landscape(self):
        """Analyze competitive landscape"""
        return {
            'pricing_by_category': dict(self.extracted_data['pricing_analytics']['by_category']),
            'pricing_by_brand': dict(self.extracted_data['pricing_analytics']['by_brand']),
            'discount_patterns': self.extracted_data['pricing_analytics']['discount_patterns']
        }
    
    def _generate_pricing_recommendations(self):
        """Generate pricing recommendations for business team"""
        valid_prices = [p.get('current_price', 0) for p in self.extracted_data['products'] if p.get('current_price', 0) > 0]
        
        if not valid_prices:
            return ["Insufficient pricing data for recommendations"]
        
        avg_price = statistics.mean(valid_prices)
        median_price = statistics.median(valid_prices)
        
        recommendations = [
            f"Market average price point: ${avg_price:.2f}",
            f"Median competitive price: ${median_price:.2f}",
        ]
        
        # Add discount-based recommendations
        discounts = [p.get('discount_percent', 0) for p in self.extracted_data['products'] if p.get('discount_percent', 0) > 0]
        if discounts:
            avg_discount = statistics.mean(discounts)
            recommendations.append(f"Average market discount: {avg_discount:.1f}%")
        
        return recommendations

def main():
    """Execute enhanced Poshmark competitive intelligence analysis"""
    print("🎯 ENHANCED POSHMARK COMPETITIVE INTELLIGENCE SYSTEM")
    print("🚀 PRICING TEAM FOCUSED ANALYSIS")
    print("=" * 70)
    
    # Initialize the intelligence system
    poshmark = PoshmarkCompetitiveIntelligence()
    
    print(f"✅ SYSTEM INITIALIZED")
    print(f"🔐 Authentication: OAuth token extracted")
    print(f"📱 Target: Poshmark iOS App APIs")
    print(f"⏰ Started at: {datetime.now().isoformat()}")
    
    # Enhanced competitive intelligence scenarios for pricing team
    print(f"\n🎯 EXECUTING ENHANCED PRICING INTELLIGENCE SCENARIOS...")
    
    # 1. Comprehensive product search and pricing analysis
    search_terms = ["designer jeans", "luxury handbags", "nike shoes", "coach bags", "lululemon"]
    pricing_data = poshmark.competitive_price_monitoring(search_terms)
    
    # 2. Generate pricing intelligence report
    final_report = poshmark.generate_pricing_intelligence_report()
    
    print(f"\n🎯 ENHANCED COMPETITIVE INTELLIGENCE EXTRACTION COMPLETE")
    print(f"💰 Pricing insights ready for strategic decision-making")
    print("=" * 70)
    
    return final_report

if __name__ == "__main__":
    main()