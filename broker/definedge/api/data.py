import http.client
import json
import pandas as pd
from datetime import datetime, timedelta
from database.token_db import get_br_symbol, get_token, get_oa_symbol
from utils.logging import get_logger

logger = get_logger(__name__)

def authenticate_broker(api_token, api_secret, otp):
    """
    Authenticate with DefinedGe Securities broker
    Returns: (auth_token, error_message)
    """
    try:
        from broker.definedge.api.auth_api import authenticate_broker as auth_broker
        return auth_broker(api_token, api_secret, otp)
    except Exception as e:
        logger.error(f"Authentication failed: {e}")
        return None, str(e)

def get_quotes(symbol, exchange, auth_token):
    """Get real-time quotes for a symbol"""
    try:
        api_session_key, susertoken, api_token = auth_token.split(":::")

        conn = http.client.HTTPSConnection("data.definedgesecurities.com")

        # Get token for the symbol
        from database.token_db import get_token
        token_id = get_token(symbol, exchange)

        headers = {
            'Authorization': api_session_key,
            'Content-Type': 'application/json'
        }

        # Use the correct DefinedGe quotes endpoint: /quotes/{exchange}/{token}
        endpoint = f"/quotes/{exchange}/{token_id}"
        
        conn.request("GET", endpoint, '', headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        return json.loads(data)

    except Exception as e:
        logger.error(f"Error getting quotes: {e}")
        return {"status": "error", "message": str(e)}

def get_security_info(symbol, exchange, auth_token):
    """Get security information"""
    try:
        api_session_key, susertoken, api_token = auth_token.split(":::")

        conn = http.client.HTTPSConnection("integrate.definedgesecurities.com")

        headers = {
            'Authorization': api_session_key,
            'Content-Type': 'application/json'
        }

        payload = json.dumps({
            "exchange": exchange,
            "tradingsymbol": symbol
        })

        conn.request("POST", "/dart/v1/security_info", payload, headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        return json.loads(data)

    except Exception as e:
        logger.error(f"Error getting security info: {e}")
        return {"status": "error", "message": str(e)}

def get_margin_info(auth_token):
    """Get margin information"""
    try:
        api_session_key, susertoken, api_token = auth_token.split(":::")

        conn = http.client.HTTPSConnection("integrate.definedgesecurities.com")

        headers = {
            'Authorization': api_session_key,
            'Content-Type': 'application/json'
        }

        conn.request("GET", "/dart/v1/margin", '', headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        return json.loads(data)

    except Exception as e:
        logger.error(f"Error getting margin info: {e}")
        return {"status": "error", "message": str(e)}

def get_limits(auth_token):
    """Get account limits"""
    try:
        api_session_key, susertoken, api_token = auth_token.split(":::")

        conn = http.client.HTTPSConnection("integrate.definedgesecurities.com")

        headers = {
            'Authorization': api_session_key,
            'Content-Type': 'application/json'
        }

        conn.request("GET", "/dart/v1/limits", '', headers)
        res = conn.getresponse()
        data = res.read().decode("utf-8")

        return json.loads(data)

    except Exception as e:
        logger.error(f"Error getting limits: {e}")
        return {"status": "error", "message": str(e)}

class BrokerData:
    def __init__(self, auth_token):
        """Initialize DefinedGe data handler with authentication token"""
        self.auth_token = auth_token
        # Map common timeframe format to DefinedGe resolutions
        self.timeframe_map = {
            # Minutes
            '1m': '1',
            '3m': '3',
            '5m': '5',
            '10m': '10',
            '15m': '15',
            '30m': '30',
            # Hours
            '1h': '60',
            # Daily
            'D': '1D'
        }

    def get_quotes(self, symbol: str, exchange: str) -> dict:
        """
        Get real-time quotes for given symbol
        Args:
            symbol: Trading symbol
            exchange: Exchange (e.g., NSE, BSE, NFO, BFO, CDS, MCX)
        Returns:
            dict: Quote data with required fields
        """
        try:
            # Use the updated get_quotes function with correct endpoint
            response = get_quotes(symbol, exchange, self.auth_token)
            
            if response.get('status') == 'error':
                raise Exception(response.get('message', 'Unknown error'))
            
            # Return quote in common format
            return {
                'bid': float(response.get('bid', 0)),
                'ask': float(response.get('ask', 0)),
                'open': float(response.get('open', 0)),
                'high': float(response.get('high', 0)),
                'low': float(response.get('low', 0)),
                'ltp': float(response.get('ltp', 0)),
                'prev_close': float(response.get('prev_close', 0)),
                'volume': int(response.get('volume', 0)),
                'oi': int(response.get('oi', 0))
            }
            
        except Exception as e:
            raise Exception(f"Error fetching quotes: {str(e)}")

    def get_history(self, symbol: str, exchange: str, interval: str, 
                   start_date: str, end_date: str) -> pd.DataFrame:
        """
        Get historical data for given symbol
        Args:
            symbol: Trading symbol
            exchange: Exchange (e.g., NSE, BSE, NFO, BFO, CDS, MCX)
            interval: Candle interval (1m, 3m, 5m, 10m, 15m, 30m, 1h, D)
            start_date: Start date (YYYY-MM-DD)
            end_date: End date (YYYY-MM-DD)
        Returns:
            pd.DataFrame: Historical data with columns [timestamp, open, high, low, close, volume, oi]
        """
        try:
            # Convert symbol to broker format and get token
            br_symbol = get_br_symbol(symbol, exchange)
            token = get_token(symbol, exchange)
            
            logger.debug(f"Debug - Broker Symbol: {br_symbol}, Token: {token}")

            # Check for unsupported timeframes
            if interval not in self.timeframe_map:
                supported = list(self.timeframe_map.keys())
                logger.warning(f"Timeframe '{interval}' is not supported by DefinedGe. Supported timeframes are: {', '.join(supported)}")
                # Return empty DataFrame instead of raising exception
                return pd.DataFrame(columns=['close', 'high', 'low', 'open', 'timestamp', 'volume', 'oi'])
            
            # Convert dates to datetime objects
            from_date = pd.to_datetime(start_date)
            to_date = pd.to_datetime(end_date)
            
            # Get historical data from DefinedGe API using correct endpoint
            api_session_key, susertoken, api_token = self.auth_token.split(":::")
            
            headers = {
                'Authorization': api_session_key,
                'Content-Type': 'application/json'
            }
            
            # Use the correct DefinedGe historical data endpoint format
            # GET https://data.definedgesecurities.com/sds/history/{segment}/{token}/{timeframe}/{from}/{to}
            
            # Map timeframe to DefinedGe format
            if interval == 'D':
                timeframe = 'day'
            elif interval.endswith('m'):
                timeframe = 'minute'
            else:
                timeframe = 'minute'  # Default to minute for other intervals
            
            # Format dates as ddMMyyyyHHmm
            from_date_str = from_date.strftime('%d%m%Y0915')
            to_date_str = to_date.strftime('%d%m%Y1530')
            
            # Convert exchange to segment format
            segment = exchange.upper()
            
            # Build the endpoint URL
            endpoint = f"/sds/history/{segment}/{token}/{timeframe}/{from_date_str}/{to_date_str}"
            
            logger.debug(f"Debug - DefinedGe API endpoint: {endpoint}")
            
            try:
                conn = http.client.HTTPSConnection("data.definedgesecurities.com")
                conn.request("GET", endpoint, '', headers)
                res = conn.getresponse()
                data = res.read().decode("utf-8")
                
                logger.debug(f"Debug - Response status: {res.status}")
                logger.debug(f"Debug - Response data: {data}")
                
                if res.status != 200:
                    logger.warning(f"Debug - DefinedGe API returned status {res.status}")
                    return pd.DataFrame(columns=['close', 'high', 'low', 'open', 'timestamp', 'volume', 'oi'])
                
                # Parse CSV response (no headers)
                # Format: Dateandtime, Open Price, High Price, Low Price, Close, Volume, Open Interest
                lines = data.strip().split('\n')
                df_data = []
                
                for line in lines:
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 6:
                            try:
                                # Parse datetime (ddMMyyyyHHmm format)
                                dt_str = parts[0].strip()
                                if len(dt_str) >= 12:
                                    dt = pd.to_datetime(dt_str, format='%d%m%Y%H%M')
                                    timestamp = int(dt.timestamp())
                                else:
                                    continue
                                
                                df_data.append({
                                    'timestamp': timestamp,
                                    'open': float(parts[1]),
                                    'high': float(parts[2]),
                                    'low': float(parts[3]),
                                    'close': float(parts[4]),
                                    'volume': int(float(parts[5])),
                                    'oi': int(float(parts[6])) if len(parts) > 6 else 0
                                })
                            except (ValueError, IndexError) as e:
                                logger.debug(f"Debug - Skipping invalid line: {line}, error: {e}")
                                continue
                
                if not df_data:
                    logger.warning("Debug - No valid data found in CSV response")
                    return pd.DataFrame(columns=['close', 'high', 'low', 'open', 'timestamp', 'volume', 'oi'])
                
                # Create DataFrame
                df = pd.DataFrame(df_data)
                
                # Sort by timestamp and remove duplicates
                df = df.sort_values('timestamp').drop_duplicates(subset=['timestamp']).reset_index(drop=True)
                
                # Reorder columns to match expected format
                df = df[['close', 'high', 'low', 'open', 'timestamp', 'volume', 'oi']]
                
                logger.debug(f"Debug - Successfully parsed {len(df)} candles")
                return df
                
            except Exception as api_error:
                logger.warning(f"Debug - DefinedGe API error: {str(api_error)}")
                return pd.DataFrame(columns=['close', 'high', 'low', 'open', 'timestamp', 'volume', 'oi'])
            
            
        except Exception as e:
            logger.warning(f"Debug - DefinedGe historical data error: {str(e)}")
            # Return empty DataFrame instead of raising exception to prevent system crashes
            return pd.DataFrame(columns=['close', 'high', 'low', 'open', 'timestamp', 'volume', 'oi'])

    def get_depth(self, symbol: str, exchange: str) -> dict:
        """
        Get market depth for given symbol
        Args:
            symbol: Trading symbol
            exchange: Exchange (e.g., NSE, BSE, NFO, BFO, CDS, MCX)
        Returns:
            dict: Market depth data with bids, asks and other details
        """
        try:
            # Convert symbol to broker format and get token
            br_symbol = get_br_symbol(symbol, exchange)
            token = get_token(symbol, exchange)
            
            api_session_key, susertoken, api_token = self.auth_token.split(":::")
            
            conn = http.client.HTTPSConnection("data.definedgesecurities.com")
            
            headers = {
                'Authorization': api_session_key,
                'Content-Type': 'application/json'
            }
            
            # Use the correct DefinedGe quotes endpoint for depth data
            endpoint = f"/quotes/{exchange}/{token}"
            
            conn.request("GET", endpoint, '', headers)
            res = conn.getresponse()
            data = res.read().decode("utf-8")
            
            response = json.loads(data)
            
            if res.status != 200:
                raise Exception(f"Error from DefinedGe API: HTTP {res.status}")
            
            depth_data = response.get('data', response)
            
            # Format bids and asks with exactly 5 entries each
            bids = []
            asks = []
            
            # Process buy orders (top 5)
            buy_orders = depth_data.get('bids', [])
            for i in range(5):
                if i < len(buy_orders):
                    bid = buy_orders[i]
                    bids.append({
                        'price': bid.get('price', 0),
                        'quantity': bid.get('quantity', 0)
                    })
                else:
                    bids.append({'price': 0, 'quantity': 0})
            
            # Process sell orders (top 5)
            sell_orders = depth_data.get('asks', [])
            for i in range(5):
                if i < len(sell_orders):
                    ask = sell_orders[i]
                    asks.append({
                        'price': ask.get('price', 0),
                        'quantity': ask.get('quantity', 0)
                    })
                else:
                    asks.append({'price': 0, 'quantity': 0})
            
            # Return depth data in common format
            return {
                'bids': bids,
                'asks': asks,
                'high': depth_data.get('high', 0),
                'low': depth_data.get('low', 0),
                'ltp': depth_data.get('ltp', 0),
                'ltq': depth_data.get('ltq', 0),
                'open': depth_data.get('open', 0),
                'prev_close': depth_data.get('prev_close', 0),
                'volume': depth_data.get('volume', 0),
                'oi': depth_data.get('oi', 0),
                'totalbuyqty': depth_data.get('totalbuyqty', 0),
                'totalsellqty': depth_data.get('totalsellqty', 0)
            }
            
        except Exception as e:
            raise Exception(f"Error fetching market depth: {str(e)}")
