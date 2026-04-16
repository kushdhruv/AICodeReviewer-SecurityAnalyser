
import pickle
import yaml

def load_session(data):
    # Unsafe pickle load
    return pickle.loads(data)

def parse_yaml_config(yaml_str):
    # Unsafe yaml load
    return yaml.load(yaml_str, Loader=yaml.Loader)
