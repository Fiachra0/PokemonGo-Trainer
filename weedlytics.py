from datetime import date

# -*- coding: utf-8 -*-
from datetime import datetime
import argparse
import json

import requests
from flask import Flask, render_template
from requests.packages.urllib3.exceptions import InsecureRequestWarning

import config as app_config
import db
import utils

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


with open('credentials.json') as f:
    credentials = json.load(f)

with open('locales/pokemon.en.json') as f:
    pokemon_names = json.load(f)


GOOGLEMAPS_KEY = credentials.get('gmaps_key', None)
AUTO_REFRESH = 45  # refresh map every X s

#get arguments for the analytics python script
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-H',
        '--host',
        help='Set web server listening host',
        default='127.0.0.1'
    )
    parser.add_argument(
        '-P',
        '--port',
        type=int,
        help='Set web server listening port',
        default=5000
    )
    parser.add_argument(
        '-d', '--debug', help='Debug Mode', action='store_true'
    )
    parser.set_defaults(DEBUG=True)
    return parser.parse_args()

def create_app():
    app = Flask(__name__, template_folder='templates')
    return app

app= create_app()

@app.route('/')
def dashboard():
    return "Dashboard goes here"
        #'map.html',
        #key=GOOGLEMAPS_KEY,
        #fullmap=get_map(),
        #auto_refresh=AUTO_REFRESH * 1000


@app.route('/pokemon/<pokemon_id>')
def data():
    """Gets all the PokeMarkers via REST"""
    return pokemon_id
    
if __name__ == '__main__':
    args = get_args()
    app.run(debug=True, threaded=True, host=args.host, port=args.port)