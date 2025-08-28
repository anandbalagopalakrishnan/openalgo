import json
from database.token_db import get_symbol, get_oa_symbol
from utils.logging import get_logger

logger = get_logger(__name__)


def map_order_data(order_data):
    """
    Processes and modifies a list of order dictionaries for DefinedGe Securities.
    
    Parameters:
    - order_data: A dictionary containing order data from DefinedGe API
    
    Returns:
    - The modified order_data with updated 'tradingsymbol' fields
    """
    # Handle DefinedGe API response structure
    if isinstance(order_data, dict):
        if order_data.get('status') == 'SUCCESS' and 'orders' in order_data:
            orders = order_data['orders']
        elif order_data.get('status') == 'ERROR':
            logger.error(f"DefinedGe API error: {order_data.get('message', 'Unknown error')}")
            return []
        else:
            # Handle case where data might be directly in the response
            orders = order_data if isinstance(order_data, list) else []
    else:
        orders = order_data if order_data else []

    if orders:
        for order in orders:
            # Extract the exchange and symbol for the current order
            exchange = order.get('exchange', '')
            symbol = order.get('tradingsymbol', '')
            
            # Convert broker symbol to OpenAlgo format
            if symbol and exchange:
                oa_symbol = get_oa_symbol(symbol=symbol, exchange=exchange)
                if oa_symbol:
                    order['tradingsymbol'] = oa_symbol
                else:
                    logger.info(f"Symbol {symbol} on exchange {exchange} not found. Keeping original.")
                    
    return orders


def calculate_order_statistics(order_data):
    """
    Calculates statistics from DefinedGe order data.

    Parameters:
    - order_data: A list of dictionaries, where each dictionary represents an order.

    Returns:
    - A dictionary containing counts of different types of orders.
    """
    # Initialize counters
    total_buy_orders = total_sell_orders = 0
    total_completed_orders = total_open_orders = total_rejected_orders = 0

    if order_data:
        for order in order_data:
            # Count buy and sell orders (DefinedGe uses 'order_type' field)
            order_type = order.get('order_type', '').upper()
            if order_type == 'BUY':
                total_buy_orders += 1
            elif order_type == 'SELL':
                total_sell_orders += 1
            
            # Count orders based on their status (DefinedGe status mapping)
            status = order.get('order_status', '').upper()
            if status in ['COMPLETE', 'EXECUTED']:
                total_completed_orders += 1
            elif status in ['OPEN', 'PENDING']:
                total_open_orders += 1
            elif status in ['REJECTED', 'CANCELLED']:
                total_rejected_orders += 1

    # Compile and return the statistics
    return {
        'total_buy_orders': total_buy_orders,
        'total_sell_orders': total_sell_orders,
        'total_completed_orders': total_completed_orders,
        'total_open_orders': total_open_orders,
        'total_rejected_orders': total_rejected_orders
    }


def transform_order_data(orders):
    """
    Transform DefinedGe order data to OpenAlgo format.
    
    Parameters:
    - orders: List of order dictionaries from DefinedGe API
    
    Returns:
    - List of transformed order dictionaries
    """
    # Handle single dictionary case
    if isinstance(orders, dict):
        orders = [orders]

    transformed_orders = []
    
    for order in orders:
        if not isinstance(order, dict):
            logger.warning(f"Expected a dict, but found a {type(order)}. Skipping this item.")
            continue

        # Map DefinedGe order status to OpenAlgo format
        status = order.get('order_status', '').upper()
        if status in ['COMPLETE', 'EXECUTED']:
            order_status = "complete"
        elif status in ['REJECTED']:
            order_status = "rejected"
        elif status in ['TRIGGER PENDING']:
            order_status = "trigger pending"
        elif status in ['OPEN', 'PENDING']:
            order_status = "open"
        elif status in ['CANCELLED']:
            order_status = "cancelled"
        else:
            order_status = status.lower()

        transformed_order = {
            "symbol": order.get("tradingsymbol", ""),
            "exchange": order.get("exchange", ""),
            "action": order.get("order_type", ""),  # DefinedGe uses 'order_type' for BUY/SELL
            "quantity": order.get("quantity", 0),
            "price": order.get("price", 0.0),
            "trigger_price": order.get("trigger_price", 0.0),
            "pricetype": order.get("price_type", ""),  # DefinedGe uses 'price_type'
            "product": order.get("product_type", ""),  # DefinedGe uses 'product_type'
            "orderid": order.get("order_id", ""),
            "order_status": order_status,
            "timestamp": order.get("order_timestamp", order.get("timestamp", ""))
        }

        transformed_orders.append(transformed_order)

    return transformed_orders


def map_trade_data(trade_data):
    """
    Processes and modifies trade data from DefinedGe Securities.
    
    Parameters:
    - trade_data: A dictionary containing trade data from DefinedGe API
    
    Returns:
    - The modified trade_data with updated 'tradingsymbol' fields
    """
    # Handle DefinedGe API response structure for trades
    if isinstance(trade_data, dict):
        if trade_data.get('status') == 'SUCCESS' and 'trades' in trade_data:
            trades = trade_data['trades']
        elif trade_data.get('status') == 'ERROR':
            logger.error(f"DefinedGe API error: {trade_data.get('message', 'Unknown error')}")
            return []
        else:
            # Handle case where data might be directly in the response
            trades = trade_data if isinstance(trade_data, list) else []
    else:
        trades = trade_data if trade_data else []

    if trades:
        for trade in trades:
            # Extract the exchange and symbol for the current trade
            exchange = trade.get('exchange', '')
            symbol = trade.get('tradingsymbol', '')
            
            # Convert broker symbol to OpenAlgo format
            if symbol and exchange:
                oa_symbol = get_oa_symbol(symbol=symbol, exchange=exchange)
                if oa_symbol:
                    trade['tradingsymbol'] = oa_symbol
                else:
                    logger.info(f"Symbol {symbol} on exchange {exchange} not found. Keeping original.")
                    
    return trades


def transform_tradebook_data(tradebook_data):
    """
    Transform DefinedGe tradebook data to OpenAlgo format.
    
    Parameters:
    - tradebook_data: List of trade dictionaries from DefinedGe API
    
    Returns:
    - List of transformed trade dictionaries
    """
    transformed_data = []
    
    for trade in tradebook_data:
        if not isinstance(trade, dict):
            logger.warning(f"Expected a dict, but found a {type(trade)}. Skipping this item.")
            continue
            
        # Calculate trade value
        quantity = float(trade.get('quantity', 0))
        avg_price = float(trade.get('average_price', trade.get('price', 0)))
        trade_value = quantity * avg_price
        
        transformed_trade = {
            "symbol": trade.get('tradingsymbol', ''),
            "exchange": trade.get('exchange', ''),
            "product": trade.get('product_type', ''),  # DefinedGe uses 'product_type'
            "action": trade.get('order_type', ''),  # DefinedGe uses 'order_type' for BUY/SELL
            "quantity": quantity,
            "average_price": avg_price,
            "trade_value": trade_value,
            "orderid": trade.get('order_id', ''),
            "timestamp": trade.get('trade_timestamp', trade.get('timestamp', ''))
        }
        transformed_data.append(transformed_trade)
        
    return transformed_data
