from app import app
from preprocess import data

def init_data():
    print(" ***** Initializing Data *****", flush=True)
    data.process()

if __name__ == "__main__":
    init_data()
    app.run(host='0.0.0.0', debug=False)