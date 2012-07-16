#include <cstdlib>
#include <iostream>

#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>

using namespace std;

enum {max_length = 1024};

class client
{
public:
	client(boost::asio::io_service& io_service,
		boost::asio::ssl::context& context,
		boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
		: socket_(io_service, context)
	{
		boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
		//socket_.set_verify_mode(boost::asio::ssl::verify_peer);
		//socket_.set_verify_callback(
				//boost::bind(&client::verify_certificate, this, _1, _2));

		//boost::asio::async_connect(socket_.lowest_layer(), endpoint_iterator,
				//boost::bind(&client::handle_connect, this,
					//boost::asio::placeholders::error));
	}

/*
	bool verify_certificate(bool perverified,
			boost::asio::ssl::verify_context& ctx)
	{
		char subject_name[256];
		X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handler());
		X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
		std::cout << "Verifying " << subject_name << endl;

		return preverified;
	}
	*/

	void handle_connect(const boost::system::error_code& error,
			boost::asio::ip::tcp::resolver::iterator endpoint_iterator)
	{
		if (!error)
			socket_.async_handshake(boost::asio::ssl::stream_base::client,
				boost::bind(&client::handle_handshake, this,
					boost::asio::placeholders::error));
		else if (endpoint_iterator != boost::asio::ip::tcp::resolver::iterator()) {
			socket_.lowest_layer().close();
			boost::asio::ip::tcp::endpoint endpoint = *endpoint_iterator;
			socket_.lowest_layer().async_connect(endpoint,
				boost::bind(&client::handle_connect, this,
					boost::asio::placeholders::error, ++endpoint_iterator));
		} else
			std::cout << "Connect failed: " << error.message() << endl;
	}

	void handle_handshake(const boost::system::error_code& error)
	{
		if (!error) {
			std::cout << "Enter message: ";
			std::cin.getline(request_, max_length);
			size_t request_length = strlen(request_);

			boost::asio::async_write(socket_,
				boost::asio::buffer(request_, request_length),
				boost::bind(&client::handle_write, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		} else
			std::cout << "Handshake failed: " << error.message() << endl;
	}

	void handle_write(const boost::system::error_code& error,
			size_t bytes_transferred)
	{
		if (!error)
			boost::asio::async_read(socket_,
				boost::asio::buffer(reply_, bytes_transferred),
				boost::bind(&client::handle_read, this,
					boost::asio::placeholders::error,
					boost::asio::placeholders::bytes_transferred));
		else
			std::cout << "Write failed: " << error.message() << endl;
	}

	void handle_read(const boost::system::error_code& error,
			size_t bytes_transferred)
	{
		if (!error) {
			std::cout << "Replay: ";
			std::cout.write(reply_, bytes_transferred);
			std::cout << endl;
		} else
			std::cout << "Read failed: " << error.message() << endl;
	}

private:
	boost::asio::ssl::stream<boost::asio::ip::tcp::socket> socket_;
	char request_[max_length];
	char reply_[max_length];
};

int main(int argc, char* argv[])
{
	try {
		if (argc != 3) {
			std::cerr << "Usage: %s <host> <port>\n";
			return 1;
		}

		boost::asio::io_service io_service;

		boost::asio::ip::tcp::resolver resolver(io_service);
		boost::asio::ip::tcp::resolver::query query(argv[1], argv[2]);
		boost::asio::ip::tcp::resolver::iterator iterator = resolver.resolve(query);

		boost::asio::ssl::context ctx(io_service, boost::asio::ssl::context::sslv23);
		ctx.set_verify_mode(boost::asio::ssl::context::verify_peer);
		ctx.load_verify_file("ca.pem");

		client c(io_service, ctx, iterator);

		io_service.run();
	} catch (std::exception& e) {
		std::cerr << "Exception: " << e.what() << endl;
	}

	return 0;
}
