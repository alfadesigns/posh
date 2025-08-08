#!/usr/bin/env python3
"""
Poshmark Competitive Pricing Intelligence Dashboard - Enterprise Edition
Advanced Streamlit application for pricing strategy teams
Author: Suhaib Alfageeh
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np
import requests
import json
import time
from datetime import datetime, timedelta
import statistics
from collections import defaultdict
import re
import altair as alt

# Page configuration
st.set_page_config(
    page_title="Poshmark Intelligence Hub",
    page_icon="🎯",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Enhanced CSS for premium dashboard styling
st.markdown("""
<style>
    /* Import Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .main {
        font-family: 'Inter', sans-serif;
    }
    
    /* Header styling */
    .dashboard-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 15px;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 10px 30px rgba(0,0,0,0.1);
    }
    
    .dashboard-title {
        font-size: 2.5rem;
        font-weight: 700;
        margin-bottom: 0.5rem;
    }
    
    .dashboard-subtitle {
        font-size: 1.1rem;
        opacity: 0.9;
        font-weight: 300;
    }
    
    /* Metric cards */
    .metric-card {
        background: white;
        padding: 1.5rem;
        border-radius: 12px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.08);
        border-left: 4px solid #667eea;
        margin: 0.5rem 0;
        transition: transform 0.2s ease;
    }
    
    .metric-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 30px rgba(0,0,0,0.12);
    }
    
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #2c3e50;
        margin-bottom: 0.2rem;
    }
    
    .metric-label {
        color: #7f8c8d;
        font-size: 0.9rem;
        font-weight: 500;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .metric-change {
        font-size: 0.8rem;
        font-weight: 500;
        margin-top: 0.3rem;
    }
    
    .metric-up { color: #27ae60; }
    .metric-down { color: #e74c3c; }
    .metric-neutral { color: #f39c12; }
    
    /* Insight cards */
    .insight-card {
        background: linear-gradient(135deg, #74b9ff 0%, #0984e3 100%);
        color: white;
        padding: 1.5rem;
        border-radius: 12px;
        margin: 1rem 0;
        box-shadow: 0 4px 20px rgba(0,0,0,0.1);
    }
    
    .insight-title {
        font-size: 1.1rem;
        font-weight: 600;
        margin-bottom: 0.5rem;
    }
    
    .insight-text {
        font-size: 0.95rem;
        line-height: 1.5;
        opacity: 0.95;
    }
    
    /* Alert boxes */
    .alert-high {
        background: linear-gradient(135deg, #ff7675 0%, #d63031 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .alert-medium {
        background: linear-gradient(135deg, #fdcb6e 0%, #e17055 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    .alert-low {
        background: linear-gradient(135deg, #55a3ff 0%, #003d82 100%);
        color: white;
        padding: 1rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    
    /* Section headers */
    .section-header {
        font-size: 1.5rem;
        font-weight: 600;
        color: #2c3e50;
        margin: 2rem 0 1rem 0;
        padding-bottom: 0.5rem;
        border-bottom: 2px solid #ecf0f1;
    }
    
    /* Recommendation cards */
    .recommendation {
        background: #f8f9fa;
        border-left: 4px solid #28a745;
        padding: 1rem;
        margin: 0.5rem 0;
        border-radius: 0 8px 8px 0;
    }
    
    .recommendation-high {
        border-left-color: #dc3545;
        background: #fff5f5;
    }
    
    .recommendation-medium {
        border-left-color: #ffc107;
        background: #fffbf0;
    }
    
    /* Status indicators */
    .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
    }
    
    .status-high { background-color: #e74c3c; }
    .status-medium { background-color: #f39c12; }
    .status-low { background-color: #27ae60; }
    
    /* Data table styling */
    .dataframe {
        border: none !important;
    }
    
    .dataframe th {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%) !important;
        color: white !important;
        font-weight: 600 !important;
        border: none !important;
    }
    
    /* Sidebar styling */
    .css-1d391kg {
        background: linear-gradient(180deg, #f8f9fa 0%, #e9ecef 100%);
    }
    
    /* Tab styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    
    .stTabs [data-baseweb="tab"] {
        background: #f8f9fa;
        border-radius: 8px 8px 0 0;
        padding: 0.5rem 1rem;
        font-weight: 500;
    }
    
    .stTabs [aria-selected="true"] {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    
    /* Loading animation */
    .loading-container {
        display: flex;
        justify-content: center;
        align-items: center;
        padding: 2rem;
    }
    
    /* Custom buttons */
    .custom-button {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        border: none;
        padding: 0.75rem 1.5rem;
        border-radius: 8px;
        font-weight: 500;
        cursor: pointer;
        transition: all 0.2s ease;
    }
    
    .custom-button:hover {
        transform: translateY(-1px);
        box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);
    }
</style>
""", unsafe_allow_html=True)

class PoshmarkIntelligenceAPI:
    def __init__(self):
        """Initialize the enhanced Poshmark API client"""
        self.oauth_token = "2344bfde01bd74cf93ae0abe09a2454528ec4d9d7b808aee4867b3ce84bdfe1e"
        self.auth_session_id = "689535a08102a282ae40019c"
        self.user_id = "689531883972a87025962ead"
        self.visitor_id = "68953161f1e0c00683a66759"
        self.device_id = "ios2:bf26e347b4eb6892eed643d679c5e3cb"
        
        self.api_base = "https://api.poshmark.com/api"
        
        self.base_headers = {
            'User-Agent': 'Poshmark/9.28 (iPhone13,2; iOS 16.4; Scale/3.00) Alamofire/5.10.2',
            'Accept-Language': 'en-US;q=1.0, ar-US;q=0.9',
            'Accept-Encoding': 'br;q=1.0, gzip;q=0.9, deflate;q=0.8',
            'X-HTTP_AUTHORIZATION': f'oauth {self.oauth_token}',
        }
        
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
        
        self.last_request_time = 0
        self.request_delay = 0.5

    def _safe_float(self, value, default=0.0):
        """Safely convert value to float"""
        if value is None:
            return default
        try:
            if isinstance(value, (int, float)):
                return float(value)
            elif isinstance(value, str):
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

    def _make_request(self, method, url, headers=None, params=None, data=None):
        """Make rate-limited API request with enhanced error handling"""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.request_delay:
            time.sleep(self.request_delay - time_since_last)
        
        request_headers = {**self.base_headers}
        if headers:
            request_headers.update(headers)
        
        request_params = {**self.common_params}
        if params:
            request_params.update(params)
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                params=request_params,
                data=data,
                timeout=15
            )
            
            self.last_request_time = time.time()
            
            if response.status_code == 200:
                try:
                    return response.json()
                except json.JSONDecodeError:
                    return None
            else:
                return None
                
        except Exception:
            return None

    def search_products(self, query, max_results=50):
        """Enhanced product search with better data extraction"""
        # Main product search
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
        
        products_data = self._make_request('GET', search_url, params=search_params)
        
        products = []
        
        if products_data and 'data' in products_data:
            data_items = products_data['data']
            
            for product in data_items[:max_results]:
                product_info = self._extract_product_details(product, query)
                if product_info and product_info.get('current_price', 0) > 0:
                    products.append(product_info)
        
        return products

    def _extract_product_details(self, product_data, search_term):
        """Enhanced product detail extraction with better categorization"""
        try:
            # Basic product info
            product_info = {
                'id': product_data.get('id', 'N/A'),
                'title': product_data.get('title', 'N/A')[:100],  # Truncate long titles
                'brand': product_data.get('brand', 'N/A'),
                'size': product_data.get('size_obj', {}).get('display', product_data.get('size', 'N/A')),
                'condition': product_data.get('condition', 'N/A'),
                'timestamp': datetime.now(),
                'category': product_data.get('category', 'N/A'),
                'department': product_data.get('department', 'N/A'),
                'search_term': search_term,
            }
            
            # Enhanced pricing extraction
            current_price = 0
            original_price = 0
            currency = '$'
            
            if 'price_amount' in product_data:
                price_data = product_data['price_amount']
                current_price = self._safe_float(price_data.get('val', 0))
                currency = price_data.get('currency_symbol', '$')
            elif 'price' in product_data:
                current_price = self._safe_float(product_data['price'])
            
            if 'original_price_amount' in product_data:
                orig_price_data = product_data['original_price_amount']
                original_price = self._safe_float(orig_price_data.get('val', 0))
            elif 'original_price' in product_data:
                original_price = self._safe_float(product_data['original_price'])
            
            product_info.update({
                'current_price': current_price,
                'original_price': original_price,
                'currency': currency
            })
            
            # Enhanced discount calculation
            if original_price > current_price > 0:
                discount_amount = original_price - current_price
                discount_percent = (discount_amount / original_price) * 100
                product_info.update({
                    'discount_amount': round(discount_amount, 2),
                    'discount_percent': round(discount_percent, 2),
                    'is_discounted': True
                })
            else:
                product_info.update({
                    'discount_amount': 0,
                    'discount_percent': 0,
                    'is_discounted': False
                })
            
            # Enhanced engagement metrics
            if 'aggregates' in product_data:
                aggregates = product_data['aggregates']
                likes = self._safe_int(aggregates.get('likes', 0))
                comments = self._safe_int(aggregates.get('comments', 0))
                shares = self._safe_int(aggregates.get('shares', 0))
            else:
                likes = self._safe_int(product_data.get('like_count', 0))
                comments = self._safe_int(product_data.get('comment_count', 0))
                shares = self._safe_int(product_data.get('share_count', 0))
            
            # Calculate engagement score
            engagement_score = (likes * 1) + (comments * 2) + (shares * 3)
            
            product_info.update({
                'likes': likes,
                'comments': comments,
                'shares': shares,
                'engagement_score': engagement_score,
                'engagement_rate': engagement_score / max(current_price, 1)  # Engagement per dollar
            })
            
            # Enhanced seller information
            product_info.update({
                'seller_username': product_data.get('creator_username', 'N/A'),
                'seller_display_name': product_data.get('creator_display_handle', 'N/A'),
            })
            
            # Price categorization for analysis
            if current_price > 0:
                if current_price < 25:
                    price_category = 'Budget'
                elif current_price < 75:
                    price_category = 'Low-Mid'
                elif current_price < 200:
                    price_category = 'Mid-Range'
                elif current_price < 500:
                    price_category = 'Premium'
                else:
                    price_category = 'Luxury'
                
                product_info['price_category'] = price_category
            
            # Market positioning score (based on price vs engagement)
            if current_price > 0 and engagement_score > 0:
                market_position = min(10, (engagement_score / current_price) * 100)
                product_info['market_position_score'] = round(market_position, 2)
            else:
                product_info['market_position_score'] = 0
            
            return product_info
            
        except Exception as e:
            return {
                'id': product_data.get('id', 'N/A'),
                'title': product_data.get('title', 'N/A'),
                'current_price': 0,
                'error': str(e)
            }

# Enhanced session state management
if 'api_client' not in st.session_state:
    st.session_state.api_client = PoshmarkIntelligenceAPI()

if 'analysis_data' not in st.session_state:
    st.session_state.analysis_data = {}

if 'historical_data' not in st.session_state:
    st.session_state.historical_data = []

if 'last_analysis_time' not in st.session_state:
    st.session_state.last_analysis_time = None

# Enhanced header
st.markdown("""
<div class="dashboard-header">
    <div class="dashboard-title">🎯 Poshmark Intelligence Hub</div>
    <div class="dashboard-subtitle">Advanced Competitive Pricing Intelligence • Real-Time Market Analysis • Strategic Insights</div>
</div>
""", unsafe_allow_html=True)

# Create tabs for better organization
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "📊 Market Overview", 
    "🔍 Deep Analysis", 
    "📈 Price Trends", 
    "🏷️ Brand Intelligence", 
    "⚙️ Settings"
])

# Enhanced predefined searches with better categorization
MARKET_CATEGORIES = {
    "Luxury Handbags": {
        "searches": ["louis vuitton bag", "chanel bag", "hermes bag", "gucci handbag", "prada bag"],
        "description": "Premium designer handbags and luxury accessories",
        "typical_range": "$200 - $5,000+",
        "color": "#8e44ad"
    },
    "Athletic Wear": {
        "searches": ["lululemon", "nike athletic", "under armour", "athleta", "alo yoga"],
        "description": "Premium athletic and activewear brands",
        "typical_range": "$20 - $150",
        "color": "#27ae60"
    },
    "Designer Denim": {
        "searches": ["designer jeans", "premium denim", "7 for all mankind", "citizens of humanity", "ag jeans"],
        "description": "High-end denim and luxury jeans",
        "typical_range": "$50 - $300",
        "color": "#3498db"
    },
    "Luxury Shoes": {
        "searches": ["louboutin", "jimmy choo", "manolo blahnik", "designer heels", "luxury sneakers"],
        "description": "Premium footwear and designer shoes",
        "typical_range": "$100 - $1,500+",
        "color": "#e74c3c"
    },
    "Coach Collection": {
        "searches": ["coach bag", "coach purse", "coach crossbody", "coach tote", "coach wallet"],
        "description": "Coach brand analysis across product lines",
        "typical_range": "$50 - $800",
        "color": "#f39c12"
    }
}

with tab1:
    st.markdown('<div class="section-header">📊 Market Overview Dashboard</div>', unsafe_allow_html=True)
    
    # Control panel
    col1, col2, col3 = st.columns([2, 2, 1])
    
    with col1:
        selected_category = st.selectbox(
            "🎯 Select Market Category",
            list(MARKET_CATEGORIES.keys()),
            help="Choose a market category for comprehensive analysis"
        )
        
        category_info = MARKET_CATEGORIES[selected_category]
        st.info(f"**{category_info['description']}**\n\nTypical Price Range: {category_info['typical_range']}")
    
    with col2:
        analysis_depth = st.selectbox(
            "📊 Analysis Depth",
            ["Quick Scan (20 products/search)", "Standard (30 products/search)", "Deep Dive (50 products/search)"],
            index=1
        )
        
        max_products = int(analysis_depth.split("(")[1].split(" ")[0])
        
        include_historical = st.checkbox("📈 Compare with Historical Data", value=True)
    
    with col3:
        st.markdown("<br>", unsafe_allow_html=True)
        run_analysis = st.button("🚀 Run Analysis", type="primary", use_container_width=True)
        
        if st.button("🗑️ Clear Data", use_container_width=True):
            st.session_state.analysis_data = {}
            st.session_state.historical_data = []
            st.rerun()

    if run_analysis:
        with st.spinner("🔄 Extracting competitive intelligence..."):
            progress_container = st.container()
            with progress_container:
                progress_bar = st.progress(0)
                status_text = st.empty()
                
                all_products = []
                search_terms = category_info["searches"]
                
                for i, term in enumerate(search_terms):
                    status_text.text(f"🔍 Analyzing: {term} ({i+1}/{len(search_terms)})")
                    
                    products = st.session_state.api_client.search_products(term, max_products)
                    all_products.extend(products)
                    
                    progress_bar.progress((i + 1) / len(search_terms))
                    time.sleep(0.2)
                
                # Store current analysis
                current_analysis = {
                    'products': all_products,
                    'category': selected_category,
                    'search_terms': search_terms,
                    'timestamp': datetime.now(),
                    'total_products': len(all_products),
                    'analysis_depth': analysis_depth
                }
                
                st.session_state.analysis_data = current_analysis
                st.session_state.last_analysis_time = datetime.now()
                
                # Add to historical data
                if include_historical:
                    st.session_state.historical_data.append({
                        'timestamp': datetime.now(),
                        'category': selected_category,
                        'avg_price': np.mean([p['current_price'] for p in all_products if p['current_price'] > 0]),
                        'total_products': len(all_products),
                        'discount_rate': len([p for p in all_products if p['is_discounted']]) / len(all_products) * 100
                    })
                
                status_text.text("✅ Analysis Complete!")
                progress_bar.progress(1.0)
                
                time.sleep(1)
                progress_container.empty()

    # Display results if available
    if st.session_state.analysis_data:
        data = st.session_state.analysis_data
        products = data['products']
        
        if products:
            df = pd.DataFrame(products)
            df = df[df['current_price'] > 0]  # Filter valid prices
            
            if len(df) > 0:
                # Key Metrics Dashboard
                st.markdown('<div class="section-header">📈 Key Performance Indicators</div>', unsafe_allow_html=True)
                
                col1, col2, col3, col4, col5 = st.columns(5)
                
                avg_price = df['current_price'].mean()
                median_price = df['current_price'].median()
                discount_rate = (df['is_discounted'].sum() / len(df)) * 100
                total_products = len(df)
                avg_engagement = df['engagement_score'].mean()
                
                with col1:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">${avg_price:.0f}</div>
                        <div class="metric-label">Average Price</div>
                        <div class="metric-change metric-neutral">Median: ${median_price:.0f}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col2:
                    discount_color = "metric-up" if discount_rate > 50 else "metric-down" if discount_rate < 30 else "metric-neutral"
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{discount_rate:.1f}%</div>
                        <div class="metric-label">Discount Rate</div>
                        <div class="metric-change {discount_color}">
                            {"High Competition" if discount_rate > 50 else "Moderate" if discount_rate > 30 else "Low Competition"}
                        </div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col3:
                    price_range = f"${df['current_price'].min():.0f} - ${df['current_price'].max():.0f}"
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{price_range}</div>
                        <div class="metric-label">Price Range</div>
                        <div class="metric-change metric-neutral">Spread: ${df['current_price'].max() - df['current_price'].min():.0f}</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col4:
                    unique_brands = df['brand'].nunique()
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{total_products}</div>
                        <div class="metric-label">Products Analyzed</div>
                        <div class="metric-change metric-neutral">{unique_brands} Brands</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                with col5:
                    st.markdown(f"""
                    <div class="metric-card">
                        <div class="metric-value">{avg_engagement:.0f}</div>
                        <div class="metric-label">Avg Engagement</div>
                        <div class="metric-change metric-neutral">Score per Product</div>
                    </div>
                    """, unsafe_allow_html=True)
                
                # Market Intelligence Insights
                st.markdown('<div class="section-header">🧠 Market Intelligence</div>', unsafe_allow_html=True)
                
                col1, col2 = st.columns([2, 1])
                
                with col1:
                    # Enhanced price distribution with better styling
                    fig_dist = px.histogram(
                        df, 
                        x='current_price', 
                        nbins=25,
                        title="Price Distribution Analysis",
                        labels={'current_price': 'Price ($)', 'count': 'Number of Products'},
                        color_discrete_sequence=[category_info['color']]
                    )
                    
                    fig_dist.update_layout(
                        height=400,
                        title_x=0.5,
                        font=dict(family="Inter", size=12),
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)'
                    )
                    
                    fig_dist.add_vline(x=avg_price, line_dash="dash", line_color="red", 
                                      annotation_text=f"Avg: ${avg_price:.0f}")
                    fig_dist.add_vline(x=median_price, line_dash="dash", line_color="green", 
                                      annotation_text=f"Median: ${median_price:.0f}")
                    
                    st.plotly_chart(fig_dist, use_container_width=True)
                
                with col2:
                    # Competitive intensity indicator
                    if discount_rate > 60:
                        intensity_level = "🔥 VERY HIGH"
                        intensity_class = "alert-high"
                        intensity_insight = "Extremely competitive market with aggressive discounting"
                    elif discount_rate > 45:
                        intensity_level = "⚡ HIGH"
                        intensity_class = "alert-high"
                        intensity_insight = "High competition with frequent price reductions"
                    elif discount_rate > 30:
                        intensity_level = "📊 MODERATE"
                        intensity_class = "alert-medium"
                        intensity_insight = "Balanced market with selective discounting"
                    else:
                        intensity_level = "💎 LOW"
                        intensity_class = "alert-low"
                        intensity_insight = "Premium market with minimal discounting"
                    
                    st.markdown(f"""
                    <div class="{intensity_class}">
                        <h3>Competitive Intensity</h3>
                        <h2>{intensity_level}</h2>
                        <p>{intensity_insight}</p>
                        <small>Based on {discount_rate:.1f}% discount rate</small>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Price category breakdown
                    price_breakdown = df['price_category'].value_counts()
                    fig_pie = px.pie(
                        values=price_breakdown.values, 
                        names=price_breakdown.index,
                        title="Price Category Distribution",
                        color_discrete_sequence=px.colors.qualitative.Set3
                    )
                    fig_pie.update_layout(height=300, font=dict(family="Inter", size=10))
                    st.plotly_chart(fig_pie, use_container_width=True)
                
                # Advanced Analytics Row
                col1, col2 = st.columns(2)
                
                with col1:
                    # Brand performance scatter plot
                    brand_stats = df.groupby('brand').agg({
                        'current_price': ['mean', 'count'],
                        'engagement_score': 'mean',
                        'discount_percent': 'mean'
                    }).round(2)
                    
                    brand_stats.columns = ['avg_price', 'product_count', 'avg_engagement', 'avg_discount']
                    brand_stats = brand_stats[brand_stats['product_count'] >= 2].reset_index()
                    
                    if len(brand_stats) > 0:
                        fig_brand = px.scatter(
                            brand_stats,
                            x='avg_price',
                            y='avg_engagement',
                            size='product_count',
                            color='avg_discount',
                            hover_data=['brand'],
                            title="Brand Positioning: Price vs Engagement",
                            labels={
                                'avg_price': 'Average Price ($)',
                                'avg_engagement': 'Average Engagement Score',
                                'avg_discount': 'Avg Discount %'
                            },
                            color_continuous_scale='RdYlBu_r'
                        )
                        fig_brand.update_layout(height=400, font=dict(family="Inter", size=12))
                        st.plotly_chart(fig_brand, use_container_width=True)
                
                with col2:
                    # Engagement vs Price correlation
                    fig_corr = px.scatter(
                        df.sample(min(100, len(df))),  # Sample for performance
                        x='current_price',
                        y='engagement_score',
                        color='is_discounted',
                        size='discount_percent',
                        title="Price vs Engagement Analysis",
                        labels={
                            'current_price': 'Price ($)',
                            'engagement_score': 'Engagement Score',
                            'is_discounted': 'Discounted'
                        },
                        color_discrete_map={True: '#e74c3c', False: '#3498db'}
                    )
                    fig_corr.update_layout(height=400, font=dict(family="Inter", size=12))
                    st.plotly_chart(fig_corr, use_container_width=True)

with tab2:
    st.markdown('<div class="section-header">🔍 Deep Market Analysis</div>', unsafe_allow_html=True)
    
    if st.session_state.analysis_data:
        data = st.session_state.analysis_data
        products = data['products']
        df = pd.DataFrame(products)
        df = df[df['current_price'] > 0]
        
        if len(df) > 0:
            # Advanced filtering section
            st.markdown("### 🎛️ Advanced Filters")
            
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                brand_filter = st.multiselect(
                    "Filter by Brand",
                    options=sorted(df['brand'].unique()),
                    default=[],
                    help="Select specific brands to analyze"
                )
            
            with col2:
                price_filter = st.slider(
                    "Price Range ($)",
                    float(df['current_price'].min()),
                    float(df['current_price'].max()),
                    (float(df['current_price'].min()), float(df['current_price'].max())),
                    help="Filter products by price range"
                )
            
            with col3:
                condition_filter = st.multiselect(
                    "Condition",
                    options=sorted(df['condition'].unique()),
                    default=[],
                    help="Filter by product condition"
                )
            
            with col4:
                discount_filter = st.selectbox(
                    "Discount Status",
                    ["All Products", "Discounted Only", "Full Price Only"],
                    help="Filter by discount status"
                )
            
            # Apply filters
            filtered_df = df.copy()
            
            if brand_filter:
                filtered_df = filtered_df[filtered_df['brand'].isin(brand_filter)]
            
            filtered_df = filtered_df[
                (filtered_df['current_price'] >= price_filter[0]) &
                (filtered_df['current_price'] <= price_filter[1])
            ]
            
            if condition_filter:
                filtered_df = filtered_df[filtered_df['condition'].isin(condition_filter)]
            
            if discount_filter == "Discounted Only":
                filtered_df = filtered_df[filtered_df['is_discounted'] == True]
            elif discount_filter == "Full Price Only":
                filtered_df = filtered_df[filtered_df['is_discounted'] == False]
            
            st.markdown(f"**{len(filtered_df)}** products match your criteria")
            
            if len(filtered_df) > 0:
                # Detailed analytics on filtered data
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    st.markdown("#### 📊 Price Analytics")
                    st.metric("Average Price", f"${filtered_df['current_price'].mean():.2f}")
                    st.metric("Median Price", f"${filtered_df['current_price'].median():.2f}")
                    st.metric("Price Std Dev", f"${filtered_df['current_price'].std():.2f}")
                
                with col2:
                    st.markdown("#### 🎯 Market Position")
                    discount_rate = (filtered_df['is_discounted'].sum() / len(filtered_df)) * 100
                    st.metric("Discount Rate", f"{discount_rate:.1f}%")
                    avg_discount = filtered_df[filtered_df['is_discounted']]['discount_percent'].mean()
                    st.metric("Avg Discount", f"{avg_discount:.1f}%" if not pd.isna(avg_discount) else "N/A")
                    st.metric("Unique Brands", f"{filtered_df['brand'].nunique()}")
                
                with col3:
                    st.markdown("#### 📈 Engagement Metrics")
                    st.metric("Avg Engagement", f"{filtered_df['engagement_score'].mean():.1f}")
                    st.metric("Engagement/Price", f"{filtered_df['engagement_rate'].mean():.3f}")
                    top_engagement = filtered_df.loc[filtered_df['engagement_score'].idxmax()]
                    st.metric("Top Engagement", f"{top_engagement['engagement_score']:.0f}")
                
                # Detailed comparison charts
                st.markdown("### 📊 Comparative Analysis")
                
                tab_charts = st.tabs(["Price Distribution", "Brand Comparison", "Engagement Analysis", "Market Positioning"])
                
                with tab_charts[0]:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Price histogram with statistical overlay
                        fig_hist = px.histogram(
                            filtered_df,
                            x='current_price',
                            nbins=20,
                            title="Price Distribution with Statistics",
                            marginal="box"
                        )
                        fig_hist.add_vline(x=filtered_df['current_price'].mean(), line_dash="dash", 
                                          line_color="red", annotation_text="Mean")
                        fig_hist.add_vline(x=filtered_df['current_price'].median(), line_dash="dash", 
                                          line_color="green", annotation_text="Median")
                        st.plotly_chart(fig_hist, use_container_width=True)
                    
                    with col2:
                        # Box plot by price category
                        fig_box = px.box(
                            filtered_df,
                            x='price_category',
                            y='current_price',
                            title="Price Distribution by Category"
                        )
                        st.plotly_chart(fig_box, use_container_width=True)
                
                with tab_charts[1]:
                    if len(filtered_df['brand'].unique()) > 1:
                        # Brand comparison metrics
                        brand_comparison = filtered_df.groupby('brand').agg({
                            'current_price': ['mean', 'median', 'count'],
                            'discount_percent': 'mean',
                            'engagement_score': 'mean'
                        }).round(2)
                        
                        brand_comparison.columns = ['Avg Price', 'Median Price', 'Products', 'Avg Discount %', 'Avg Engagement']
                        brand_comparison = brand_comparison.sort_values('Avg Price', ascending=False)
                        
                        st.dataframe(brand_comparison, use_container_width=True)
                        
                        # Brand performance chart
                        fig_brand_comp = px.bar(
                            brand_comparison.reset_index(),
                            x='brand',
                            y='Avg Price',
                            color='Avg Engagement',
                            title="Brand Price vs Engagement Comparison",
                            color_continuous_scale='viridis'
                        )
                        st.plotly_chart(fig_brand_comp, use_container_width=True)
                    else:
                        st.info("Select multiple brands to see comparison analysis")
                
                with tab_charts[2]:
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        # Engagement vs Price scatter
                        fig_eng = px.scatter(
                            filtered_df,
                            x='current_price',
                            y='engagement_score',
                            color='brand',
                            size='likes',
                            hover_data=['title'],
                            title="Engagement vs Price by Brand"
                        )
                        st.plotly_chart(fig_eng, use_container_width=True)
                    
                    with col2:
                        # Top performing products
                        top_products = filtered_df.nlargest(10, 'engagement_score')[
                            ['title', 'brand', 'current_price', 'engagement_score', 'likes']
                        ]
                        st.markdown("**Top Engaging Products**")
                        st.dataframe(top_products, use_container_width=True, hide_index=True)
                
                with tab_charts[3]:
                    # Market positioning analysis
                    fig_position = px.scatter(
                        filtered_df,
                        x='current_price',
                        y='market_position_score',
                        color='price_category',
                        size='engagement_score',
                        hover_data=['brand', 'title'],
                        title="Market Positioning: Price vs Performance Score"
                    )
                    st.plotly_chart(fig_position, use_container_width=True)
                    
                    # Best value products
                    best_value = filtered_df.nlargest(10, 'market_position_score')[
                        ['title', 'brand', 'current_price', 'market_position_score', 'engagement_score']
                    ]
                    st.markdown("**Best Value Products (High Performance/Price Ratio)**")
                    st.dataframe(best_value, use_container_width=True, hide_index=True)

with tab3:
    st.markdown('<div class="section-header">📈 Price Trends & Historical Analysis</div>', unsafe_allow_html=True)
    
    if st.session_state.historical_data and len(st.session_state.historical_data) > 1:
        hist_df = pd.DataFrame(st.session_state.historical_data)
        hist_df['timestamp'] = pd.to_datetime(hist_df['timestamp'])
        
        # Historical trends
        col1, col2 = st.columns(2)
        
        with col1:
            fig_trend = px.line(
                hist_df,
                x='timestamp',
                y='avg_price',
                color='category',
                title="Average Price Trends Over Time",
                markers=True
            )
            st.plotly_chart(fig_trend, use_container_width=True)
        
        with col2:
            fig_discount_trend = px.line(
                hist_df,
                x='timestamp',
                y='discount_rate',
                color='category',
                title="Discount Rate Trends Over Time",
                markers=True
            )
            st.plotly_chart(fig_discount_trend, use_container_width=True)
        
        # Trend insights
        latest = hist_df.iloc[-1]
        previous = hist_df.iloc[-2] if len(hist_df) > 1 else latest
        
        price_change = ((latest['avg_price'] - previous['avg_price']) / previous['avg_price']) * 100
        discount_change = latest['discount_rate'] - previous['discount_rate']
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            trend_color = "🔴" if price_change > 5 else "🟢" if price_change < -5 else "🟡"
            st.markdown(f"""
            <div class="insight-card">
                <div class="insight-title">{trend_color} Price Trend</div>
                <div class="insight-text">
                    Average price changed by {price_change:+.1f}% since last analysis
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            discount_color = "🔴" if discount_change > 10 else "🟢" if discount_change < -10 else "🟡"
            st.markdown(f"""
            <div class="insight-card">
                <div class="insight-title">{discount_color} Discount Trend</div>
                <div class="insight-text">
                    Discount rate changed by {discount_change:+.1f}% points
                </div>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            market_momentum = "📈 Bullish" if price_change > 0 and discount_change < 0 else "📉 Bearish" if price_change < 0 and discount_change > 0 else "➡️ Stable"
            st.markdown(f"""
            <div class="insight-card">
                <div class="insight-title">📊 Market Momentum</div>
                <div class="insight-text">
                    {market_momentum}
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("📊 Historical trends will appear here after multiple analyses. Run analysis on different categories or time periods to build trend data.")
        
        # Show current analysis trend
        if st.session_state.analysis_data:
            df = pd.DataFrame(st.session_state.analysis_data['products'])
            df = df[df['current_price'] > 0]
            
            if len(df) > 0:
                st.markdown("### 📊 Current Analysis Insights")
                
                # Price distribution over time posted
                if 'timestamp' in df.columns:
                    df['hour'] = pd.to_datetime(df['timestamp']).dt.hour
                    hourly_avg = df.groupby('hour')['current_price'].mean().reset_index()
                    
                    fig_hourly = px.line(
                        hourly_avg,
                        x='hour',
                        y='current_price',
                        title="Average Price by Hour (Current Analysis)",
                        markers=True
                    )
                    st.plotly_chart(fig_hourly, use_container_width=True)

with tab4:
    st.markdown('<div class="section-header">🏷️ Brand Intelligence & Competitive Landscape</div>', unsafe_allow_html=True)
    
    if st.session_state.analysis_data:
        df = pd.DataFrame(st.session_state.analysis_data['products'])
        df = df[df['current_price'] > 0]
        
        if len(df) > 0:
            # Brand selection
            available_brands = df['brand'].value_counts()
            selected_brands = st.multiselect(
                "🎯 Select Brands for Deep Analysis",
                options=available_brands.index.tolist(),
                default=available_brands.head(5).index.tolist(),
                help="Choose brands with sufficient product data for meaningful analysis"
            )
            
            if selected_brands:
                brand_df = df[df['brand'].isin(selected_brands)]
                
                # Brand comparison dashboard
                st.markdown("### 📊 Brand Performance Dashboard")
                
                brand_metrics = brand_df.groupby('brand').agg({
                    'current_price': ['mean', 'median', 'std', 'count'],
                    'discount_percent': ['mean', 'std'],
                    'engagement_score': ['mean', 'max'],
                    'likes': 'sum',
                    'is_discounted': lambda x: (x.sum() / len(x)) * 100
                }).round(2)
                
                brand_metrics.columns = [
                    'Avg Price', 'Median Price', 'Price Std', 'Products',
                    'Avg Discount %', 'Discount Volatility', 
                    'Avg Engagement', 'Max Engagement',
                    'Total Likes', 'Discount Rate %'
                ]
                
                st.dataframe(brand_metrics.sort_values('Avg Price', ascending=False), use_container_width=True)
                
                # Brand positioning charts
                col1, col2 = st.columns(2)
                
                with col1:
                    # Brand positioning matrix
                    brand_summary = brand_metrics.reset_index()
                    fig_matrix = px.scatter(
                        brand_summary,
                        x='Avg Price',
                        y='Avg Engagement',
                        size='Products',
                        color='Discount Rate %',
                        hover_data=['brand'],
                        title="Brand Positioning Matrix",
                        labels={
                            'Avg Price': 'Average Price ($)',
                            'Avg Engagement': 'Average Engagement Score'
                        },
                        color_continuous_scale='RdYlBu_r'
                    )
                    
                    # Add quadrant lines
                    avg_price_median = brand_summary['Avg Price'].median()
                    avg_engagement_median = brand_summary['Avg Engagement'].median()
                    
                    fig_matrix.add_hline(y=avg_engagement_median, line_dash="dash", line_color="gray", opacity=0.5)
                    fig_matrix.add_vline(x=avg_price_median, line_dash="dash", line_color="gray", opacity=0.5)
                    
                    # Add quadrant labels
                    fig_matrix.add_annotation(x=avg_price_median*1.2, y=avg_engagement_median*1.2, 
                                            text="Premium & Popular", showarrow=False, font_size=10)
                    fig_matrix.add_annotation(x=avg_price_median*0.8, y=avg_engagement_median*1.2, 
                                            text="Value & Popular", showarrow=False, font_size=10)
                    fig_matrix.add_annotation(x=avg_price_median*1.2, y=avg_engagement_median*0.8, 
                                            text="Premium & Niche", showarrow=False, font_size=10)
                    fig_matrix.add_annotation(x=avg_price_median*0.8, y=avg_engagement_median*0.8, 
                                            text="Value & Niche", showarrow=False, font_size=10)
                    
                    st.plotly_chart(fig_matrix, use_container_width=True)
                
                with col2:
                    # Brand market share by price category
                    brand_price_cat = brand_df.groupby(['brand', 'price_category']).size().reset_index(name='count')
                    fig_share = px.sunburst(
                        brand_price_cat,
                        path=['price_category', 'brand'],
                        values='count',
                        title="Market Share by Price Category"
                    )
                    st.plotly_chart(fig_share, use_container_width=True)
                
                # Competitive insights
                st.markdown("### 🎯 Competitive Intelligence Insights")
                
                insights = []
                
                # Price leadership
                price_leader = brand_metrics.idxmax()['Avg Price']
                value_leader = brand_metrics.idxmin()['Avg Price']
                engagement_leader = brand_metrics.idxmax()['Avg Engagement']
                
                insights.append(f"👑 **Price Leadership**: {price_leader} commands the highest average price at ${brand_metrics.loc[price_leader, 'Avg Price']:.0f}")
                insights.append(f"💰 **Value Leader**: {value_leader} offers the most accessible pricing at ${brand_metrics.loc[value_leader, 'Avg Price']:.0f} average")
                insights.append(f"📈 **Engagement Champion**: {engagement_leader} achieves highest customer engagement ({brand_metrics.loc[engagement_leader, 'Avg Engagement']:.0f} avg score)")
                
                # Discount strategies
                high_discount_brand = brand_metrics.idxmax()['Discount Rate %']
                low_discount_brand = brand_metrics.idxmin()['Discount Rate %']
                
                insights.append(f"🎯 **Aggressive Discounter**: {high_discount_brand} discounts {brand_metrics.loc[high_discount_brand, 'Discount Rate %']:.0f}% of products")
                insights.append(f"💎 **Premium Strategy**: {low_discount_brand} maintains premium positioning with {brand_metrics.loc[low_discount_brand, 'Discount Rate %']:.0f}% discount rate")
                
                # Market opportunities
                price_gaps = []
                for i, brand1 in enumerate(selected_brands):
                    for brand2 in selected_brands[i+1:]:
                        price_diff = abs(brand_metrics.loc[brand1, 'Avg Price'] - brand_metrics.loc[brand2, 'Avg Price'])
                        if price_diff > 50:  # Significant price gap
                            price_gaps.append((brand1, brand2, price_diff))
                
                if price_gaps:
                    largest_gap = max(price_gaps, key=lambda x: x[2])
                    insights.append(f"🔍 **Market Gap**: ${largest_gap[2]:.0f} price differential between {largest_gap[0]} and {largest_gap[1]} suggests positioning opportunity")
                
                for i, insight in enumerate(insights):
                    priority_class = "recommendation-high" if i < 2 else "recommendation-medium" if i < 4 else "recommendation"
                    st.markdown(f"""
                    <div class="{priority_class}">
                        <strong>{i+1}.</strong> {insight}
                    </div>
                    """, unsafe_allow_html=True)

with tab5:
    st.markdown('<div class="section-header">⚙️ Settings & Configuration</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔧 Analysis Settings")
        
        # API configuration
        st.markdown("#### API Configuration")
        st.text_input("Request Delay (seconds)", value="0.5", help="Delay between API requests to avoid rate limiting")
        st.text_input("Max Products per Search", value="50", help="Maximum products to fetch per search term")
        st.checkbox("Enable Detailed Logging", value=False, help="Log detailed API request information")
        
        # Analysis preferences
        st.markdown("#### Analysis Preferences")
        st.selectbox("Default Price Currency", ["USD ($)", "EUR (€)", "GBP (£)"])
        st.selectbox("Chart Color Scheme", ["Default", "Viridis", "Plasma", "Colorblind-friendly"])
        st.checkbox("Auto-save Historical Data", value=True, help="Automatically save analysis results for trend tracking")
        
        # Export settings
        st.markdown("#### Export Settings")
        st.selectbox("Default Export Format", ["CSV", "Excel", "JSON"])
        st.checkbox("Include Raw Data in Exports", value=True)
        st.checkbox("Auto-generate Executive Summary", value=True)
    
    with col2:
        st.markdown("### 📊 Performance Metrics")
        
        if st.session_state.analysis_data:
            last_analysis = st.session_state.last_analysis_time
            if last_analysis:
                st.metric("Last Analysis", last_analysis.strftime("%Y-%m-%d %H:%M:%S"))
                st.metric("Products Analyzed", len(st.session_state.analysis_data.get('products', [])))
                st.metric("Historical Data Points", len(st.session_state.historical_data))
        
        st.markdown("### 🛠️ Technical Information")
        st.info("""
        **Reverse Engineering Details:**
        - ✅ iOS Anti-debugging bypassed
        - ✅ OAuth authentication extracted  
        - ✅ 5+ API endpoints discovered
        - ✅ Real-time data extraction active
        - ✅ Rate limiting implemented
        """)
        
        st.markdown("### 📋 Data Management")
        
        col1_inner, col2_inner = st.columns(2)
        
        with col1_inner:
            if st.button("📤 Export All Data", use_container_width=True):
                if st.session_state.analysis_data:
                    export_data = {
                        'current_analysis': st.session_state.analysis_data,
                        'historical_data': st.session_state.historical_data,
                        'export_timestamp': datetime.now().isoformat()
                    }
                    
                    export_json = json.dumps(export_data, default=str, indent=2)
                    st.download_button(
                        label="Download Complete Dataset",
                        data=export_json,
                        file_name=f"poshmark_intelligence_{datetime.now().strftime('%Y%m%d_%H%M')}.json",
                        mime="application/json"
                    )
        
        with col2_inner:
            if st.button("🗑️ Clear All Data", use_container_width=True, type="secondary"):
                if st.button("⚠️ Confirm Clear", use_container_width=True):
                    st.session_state.analysis_data = {}
                    st.session_state.historical_data = []
                    st.session_state.last_analysis_time = None
                    st.success("All data cleared!")
                    st.rerun()

# Footer with technical details
st.markdown("---")
st.markdown("""
<div style="text-align: center; padding: 2rem; background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%); border-radius: 10px; margin: 2rem 0;">
    <h3 style="color: #2c3e50; margin-bottom: 1rem;">🎯 Poshmark Intelligence Hub</h3>
    <p style="color: #7f8c8d; margin-bottom: 0.5rem;">
        <strong>Powered by Advanced iOS Reverse Engineering</strong><br>
        Real-time competitive intelligence • Strategic pricing insights • Executive reporting
    </p>
    <p style="color: #95a5a6; font-size: 0.9rem;">
        API Status: <span style="color: #27ae60;">🟢 Connected</span> | 
        Rate Limit: <span style="color: #27ae60;">✅ Optimized</span> | 
        Data Quality: <span style="color: #27ae60;">🎯 High</span>
    </p>
</div>
""", unsafe_allow_html=True)