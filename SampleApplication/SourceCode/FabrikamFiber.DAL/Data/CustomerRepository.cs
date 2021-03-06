using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using Newtonsoft.Json;

namespace FabrikamFiber.DAL.Data
{
    using System;
    using System.Data;
    using System.Data.Entity;
    using System.Linq;
    using System.Linq.Expressions;

    using FabrikamFiber.DAL.Models;

    public interface ICustomerRepository
    {
        IQueryable<Customer> All { get; }

        IQueryable<Customer> AllIncluding(params Expression<Func<Customer, object>>[] includeProperties);

        Customer Find(int id);

        void InsertOrUpdate(Customer customer);

        void Delete(int id);

        void Save();
    }

    public class CustomerRepository : ICustomerRepository
    {

        private readonly Uri _baseAddress = new Uri(System.Configuration.ConfigurationManager.AppSettings["ApiBaseUrl"]);

        public IQueryable<Customer> All
        {
            get
            {
                var client = new HttpClient();
                client.BaseAddress = _baseAddress;
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
                HttpResponseMessage response = client.GetAsync("customer/").Result;

                if (response.IsSuccessStatusCode)
                {
                    IEnumerable<Customer> customers = response.Content.ReadAsAsync<IEnumerable<Customer>>().Result;
                    return customers.AsQueryable();
                }

                return null;
            }
        }

        public IQueryable<Customer> AllIncluding(params Expression<Func<Customer, object>>[] includeProperties)
        {
            IQueryable<Customer> query = All;

            foreach (var includeProperty in includeProperties)
            {
                query = query.Include(includeProperty);
            }

            return query;
        }

        public Customer Find(int id)
        {
            var client = new HttpClient();
            client.BaseAddress = _baseAddress;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            HttpResponseMessage response = client.GetAsync("customer/" + id).Result;

            if (response.IsSuccessStatusCode)
            {
                Customer customer = response.Content.ReadAsAsync<Customer>().Result;
                return customer;
            }

            return null;
        }

        public void InsertOrUpdate(Customer customer)
        {
            if (customer.Id == default(int))
            {
                var client = new HttpClient();
                client.BaseAddress = _baseAddress;
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                string postBody = JsonConvert.SerializeObject(customer);
                HttpResponseMessage response = client.PostAsync("customer/", new StringContent(postBody, Encoding.UTF8, "application/json")).Result;

                if (response.IsSuccessStatusCode)
                {
                    return;
                }

            }
            else
            {
                var client = new HttpClient();
                client.BaseAddress = _baseAddress;
                client.DefaultRequestHeaders.Accept.Clear();
                client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                string postBody = JsonConvert.SerializeObject(customer);
                HttpResponseMessage response = client.PutAsync("customer/" + customer.Id, new StringContent(postBody, Encoding.UTF8, "application/json")).Result;

                if (response.IsSuccessStatusCode)
                {
                    return;
                }

            }
        }

        public void Delete(int id)
        {
            var client = new HttpClient();
            client.BaseAddress = _baseAddress;
            client.DefaultRequestHeaders.Accept.Clear();
            client.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            HttpResponseMessage response = client.DeleteAsync("customer/" + id).Result;

            if (response.IsSuccessStatusCode)
            {
                return;
            }

        }

        public void Save()
        {
        }
    }
}