#database/master_contract_db.py

import os
import pandas as pd
import numpy as np
import requests
import gzip
import shutil
import http.client
import json
import pandas as pd
import gzip
import io

from sqlalchemy import create_engine, Column, Integer, String, Float, Sequence, Index
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from database.auth_db import get_auth_token
from database.user_db import find_user_by_username
from extensions import socketio  # Import SocketIO
from utils.logging import get_logger

logger = get_logger(__name__)

DATABASE_URL = os.getenv('DATABASE_URL')  # Replace with your database path

engine = create_engine(DATABASE_URL)
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()

class SymToken(Base):
    __tablename__ = 'symtoken'
    id = Column(Integer, Sequence('symtoken_id_seq'), primary_key=True)
    symbol = Column(String, nullable=False, index=True)  # Single column index
    brsymbol = Column(String, nullable=False, index=True)  # Single column index
    name = Column(String)
    exchange = Column(String, index=True)  # Include this column in a composite index
    brexchange = Column(String, index=True)
    token = Column(String, index=True)  # Indexed for performance
    expiry = Column(String)
    strike = Column(Float)
    lotsize = Column(Integer)
    instrumenttype = Column(String)
    tick_size = Column(Float)

def init_db():
    Base.metadata.create_all(bind=engine)

def delete_symtoken_table():
    """Delete all records from symtoken table"""
    try:
        db_session.query(SymToken).delete()
        db_session.commit()
        logger.info("All records deleted from symtoken table")
    except Exception as e:
        logger.error(f"Error deleting symtoken table: {e}")
        db_session.rollback()

def copy_from_dataframe(df):
    """Copy dataframe to database"""
    try:
        df.to_sql('symtoken', con=engine, if_exists='append', index=False)
        logger.info(f"Inserted {len(df)} records into symtoken table")
    except Exception as e:
        logger.error(f"Error copying dataframe to database: {e}")

def download_definedge_master_files(auth_token, output_path):
    """Download master contract files from DefinedGe Securities"""
    try:
        api_session_key, susertoken, api_token = auth_token.split(":::")

        # DefinedGe master files are available at data.definedgesecurities.com
        # Based on API documentation, master files are available for different segments
        exchanges = ['NSE', 'BSE', 'NFO', 'CDS', 'MCX', 'BFO']

        for exchange in exchanges:
            try:
                conn = http.client.HTTPSConnection("data.definedgesecurities.com")

                headers = {
                    'Authorization': api_session_key,
                    'Content-Type': 'application/json'
                }

                # Request master file for the exchange
                conn.request("GET", f"/master/{exchange.lower()}", '', headers)
                res = conn.getresponse()

                if res.status == 200:
                    data = res.read()

                    # Save the master file
                    filename = f"{exchange}_symbols.txt"
                    filepath = os.path.join(output_path, filename)

                    with open(filepath, 'wb') as f:
                        f.write(data)

                    logger.info(f"Downloaded {exchange} master file: {filename}")
                else:
                    logger.warning(f"Failed to download {exchange} master file: {res.status}")

            except Exception as e:
                logger.error(f"Error downloading {exchange} master file: {e}")

        return True

    except Exception as e:
        logger.error(f"Error downloading DefinedGe master files: {e}")
        return False

def process_definedge_nse_csv(path):
    """Process DefinedGe NSE master file"""
    try:
        df = pd.read_csv(path)

        # Map DefinedGe NSE columns to OpenAlgo schema
        # Assuming DefinedGe uses standard format: Symbol, Token, Name, etc.
        processed_df = pd.DataFrame()

        if 'Symbol' in df.columns:
            processed_df['symbol'] = df['Symbol'] + '-EQ'  # OpenAlgo format
            processed_df['brsymbol'] = df['Symbol']  # DefinedGe format

        if 'Token' in df.columns:
            processed_df['token'] = df['Token'].astype(str)

        if 'Name' in df.columns:
            processed_df['name'] = df['Name']

        processed_df['exchange'] = 'NSE'
        processed_df['brexchange'] = 'NSE'
        processed_df['expiry'] = ''
        processed_df['strike'] = 0.0
        processed_df['lotsize'] = df.get('LotSize', 1)
        processed_df['instrumenttype'] = 'EQ'
        processed_df['tick_size'] = df.get('TickSize', 0.05)

        return processed_df

    except Exception as e:
        logger.error(f"Error processing NSE CSV: {e}")
        return pd.DataFrame()

def process_definedge_bse_csv(path):
    """Process DefinedGe BSE master file"""
    try:
        df = pd.read_csv(path)

        processed_df = pd.DataFrame()

        if 'Symbol' in df.columns:
            processed_df['symbol'] = df['Symbol']  # BSE doesn't need -EQ suffix
            processed_df['brsymbol'] = df['Symbol']

        if 'Token' in df.columns:
            processed_df['token'] = df['Token'].astype(str)

        if 'Name' in df.columns:
            processed_df['name'] = df['Name']

        processed_df['exchange'] = 'BSE'
        processed_df['brexchange'] = 'BSE'
        processed_df['expiry'] = ''
        processed_df['strike'] = 0.0
        processed_df['lotsize'] = df.get('LotSize', 1)
        processed_df['instrumenttype'] = 'EQ'
        processed_df['tick_size'] = df.get('TickSize', 0.05)

        return processed_df

    except Exception as e:
        logger.error(f"Error processing BSE CSV: {e}")
        return pd.DataFrame()

def process_definedge_nfo_csv(path):
    """Process DefinedGe NFO (derivatives) master file"""
    try:
        df = pd.read_csv(path)

        processed_df = pd.DataFrame()

        if 'TradingSymbol' in df.columns:
            processed_df['symbol'] = df['TradingSymbol']
            processed_df['brsymbol'] = df['TradingSymbol']

        if 'Token' in df.columns:
            processed_df['token'] = df['Token'].astype(str)

        if 'Name' in df.columns:
            processed_df['name'] = df['Name']

        processed_df['exchange'] = 'NFO'
        processed_df['brexchange'] = 'NFO'
        processed_df['expiry'] = df.get('Expiry', '')
        processed_df['strike'] = df.get('StrikePrice', 0.0)
        processed_df['lotsize'] = df.get('LotSize', 1)
        processed_df['instrumenttype'] = df.get('InstrumentType', 'FUT')
        processed_df['tick_size'] = df.get('TickSize', 0.05)

        return processed_df

    except Exception as e:
        logger.error(f"Error processing NFO CSV: {e}")
        return pd.DataFrame()

def process_definedge_cds_csv(path):
    """Process DefinedGe CDS master file"""
    try:
        df = pd.read_csv(path)

        processed_df = pd.DataFrame()

        if 'TradingSymbol' in df.columns:
            processed_df['symbol'] = df['TradingSymbol']
            processed_df['brsymbol'] = df['TradingSymbol']

        if 'Token' in df.columns:
            processed_df['token'] = df['Token'].astype(str)

        processed_df['exchange'] = 'CDS'
        processed_df['brexchange'] = 'CDS'
        processed_df['expiry'] = df.get('Expiry', '')
        processed_df['strike'] = 0.0
        processed_df['lotsize'] = df.get('LotSize', 1)
        processed_df['instrumenttype'] = 'CUR'
        processed_df['tick_size'] = df.get('TickSize', 0.0025)

        return processed_df

    except Exception as e:
        logger.error(f"Error processing CDS CSV: {e}")
        return pd.DataFrame()

def process_definedge_mcx_csv(path):
    """Process DefinedGe MCX master file"""
    try:
        df = pd.read_csv(path)

        processed_df = pd.DataFrame()

        if 'TradingSymbol' in df.columns:
            processed_df['symbol'] = df['TradingSymbol']
            processed_df['brsymbol'] = df['TradingSymbol']

        if 'Token' in df.columns:
            processed_df['token'] = df['Token'].astype(str)

        processed_df['exchange'] = 'MCX'
        processed_df['brexchange'] = 'MCX'
        processed_df['expiry'] = df.get('Expiry', '')
        processed_df['strike'] = 0.0
        processed_df['lotsize'] = df.get('LotSize', 1)
        processed_df['instrumenttype'] = 'COM'
        processed_df['tick_size'] = df.get('TickSize', 1.0)

        return processed_df

    except Exception as e:
        logger.error(f"Error processing MCX CSV: {e}")
        return pd.DataFrame()

def process_definedge_bfo_csv(path):
    """Process DefinedGe BFO master file"""
    try:
        df = pd.read_csv(path)

        processed_df = pd.DataFrame()

        if 'TradingSymbol' in df.columns:
            processed_df['symbol'] = df['TradingSymbol']
            processed_df['brsymbol'] = df['TradingSymbol']

        if 'Token' in df.columns:
            processed_df['token'] = df['Token'].astype(str)

        processed_df['exchange'] = 'BFO'
        processed_df['brexchange'] = 'BFO'
        processed_df['expiry'] = df.get('Expiry', '')
        processed_df['strike'] = df.get('StrikePrice', 0.0)
        processed_df['lotsize'] = df.get('LotSize', 1)
        processed_df['instrumenttype'] = df.get('InstrumentType', 'FUT')
        processed_df['tick_size'] = df.get('TickSize', 0.05)

        return processed_df

    except Exception as e:
        logger.error(f"Error processing BFO CSV: {e}")
        return pd.DataFrame()

def delete_definedge_temp_data(output_path):
    """Delete temporary downloaded files"""
    try:
        exchanges = ['NSE', 'BSE', 'NFO', 'CDS', 'MCX', 'BFO']
        for exchange in exchanges:
            filename = f"{exchange}_symbols.txt"
            filepath = os.path.join(output_path, filename)
            if os.path.exists(filepath):
                os.remove(filepath)
                logger.info(f"Deleted temporary file: {filename}")
    except Exception as e:
        logger.error(f"Error deleting temporary files: {e}")

def master_contract_download():
    """Download and process DefinedGe master contracts"""
    try:
        # Get auth token for the first user (assuming single user setup)
        auth_token = get_auth_token()
        if not auth_token:
            logger.error("No auth token found for DefinedGe master contract download")
            return False

        # Create temp directory
        output_path = "tmp"
        os.makedirs(output_path, exist_ok=True)

        # Download master files
        if not download_definedge_master_files(auth_token, output_path):
            logger.error("Failed to download DefinedGe master files")
            return False

        # Delete existing data
        delete_symtoken_table()

        # Process each exchange file
        exchanges_processors = {
            'NSE': process_definedge_nse_csv,
            'BSE': process_definedge_bse_csv,
            'NFO': process_definedge_nfo_csv,
            'CDS': process_definedge_cds_csv,
            'MCX': process_definedge_mcx_csv,
            'BFO': process_definedge_bfo_csv
        }

        for exchange, processor in exchanges_processors.items():
            filepath = os.path.join(output_path, f"{exchange}_symbols.txt")
            if os.path.exists(filepath):
                try:
                    df = processor(filepath)
                    if not df.empty:
                        copy_from_dataframe(df)
                        logger.info(f"Processed {exchange} master file: {len(df)} symbols")
                    else:
                        logger.warning(f"No data processed for {exchange}")
                except Exception as e:
                    logger.error(f"Error processing {exchange} file: {e}")

        # Clean up temporary files
        delete_definedge_temp_data(output_path)

        logger.info("DefinedGe master contract download completed successfully")
        return True

    except Exception as e:
        logger.error(f"Error in DefinedGe master contract download: {e}")
        return False

def search_symbols(symbol, exchange):
    """Search for symbols in the database"""
    try:
        results = db_session.query(SymToken).filter(
            SymToken.symbol.ilike(f"%{symbol}%"),
            SymToken.exchange == exchange
        ).limit(10).all()

        return [{'symbol': r.symbol, 'token': r.token, 'name': r.name} for r in results]

    except Exception as e:
        logger.error(f"Error searching symbols: {e}")
        return []
